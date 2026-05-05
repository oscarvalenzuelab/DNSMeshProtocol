"""Tests for the M9.2.3 TSIG-key registration flow.

Mirrors test_registration.py's structure for the bearer-token flow but
targets ``mint_tsig_via_registration`` and the
``POST /v1/registration/tsig-confirm`` HTTP endpoint.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from dmp.server.registration import (
    ChallengeStore,
    RegistrationConfig,
    RegistrationError,
    SignatureInvalid,
    SubjectNotAllowed,
    _build_signing_payload,
    mint_tsig_via_registration,
)
from dmp.server.tsig_keystore import TSIGKeyStore


@pytest.fixture
def keystore(tmp_path: Path) -> TSIGKeyStore:
    s = TSIGKeyStore(str(tmp_path / "tsig.db"))
    yield s
    s.close()


@pytest.fixture
def config() -> RegistrationConfig:
    return RegistrationConfig(
        enabled=True,
        node_hostname="ops.example",
        allowlist=("ops.example",),
        expires_in_seconds=3600,
    )


@pytest.fixture
def challenges() -> ChallengeStore:
    return ChallengeStore()


def _signed_body(
    *,
    subject: str,
    challenge_hex: str,
    node: str,
) -> tuple[dict, str]:
    """Build a confirm-shape body with a fresh Ed25519 keypair. Returns
    (body, spk_hex)."""
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes_raw()
    payload = _build_signing_payload(challenge_hex, subject, node)
    sig = priv.sign(payload)
    return (
        {
            "subject": subject,
            "ed25519_spk": pub.hex(),
            "challenge": challenge_hex,
            "signature": sig.hex(),
        },
        pub.hex(),
    )


class TestMintTsigViaRegistration:
    def test_happy_path(self, keystore, config, challenges):
        pc = challenges.issue(config.node_hostname)
        body, spk_hex = _signed_body(
            subject="alice@ops.example",
            challenge_hex=pc.challenge_hex,
            node=pc.node,
        )
        minted = mint_tsig_via_registration(
            keystore=keystore,
            challenges=challenges,
            config=config,
            body=body,
        )
        # Key name encodes local part + spk prefix + subject hash + zone.
        assert minted.subject == "alice@ops.example"
        assert minted.zone == "ops.example"
        assert minted.name.startswith("alice-" + spk_hex[:8])
        assert minted.name.endswith(".ops.example.")
        # Default scope (M9.2.6 round-18 — single-user-per-zone is
        # the M9 design target). Per-user identity hashes + the
        # user's spk-prefixed claim record + wildcard owner
        # patterns covering the names ``send_message`` writes.
        # Multi-tenant operators opt out via DMP_TSIG_TIGHT_SCOPE=1.
        suffixes = set(minted.allowed_suffixes)
        assert any(s.startswith("id-") for s in suffixes)
        assert any(s.startswith("_dnsmesh-claim-" + spk_hex[:16]) for s in suffixes)
        assert "slot-*.mb-*.ops.example" in suffixes
        assert "chunk-*-*.ops.example" in suffixes
        assert "_dnsmesh-claim-*.ops.example" in suffixes
        assert "claim-*.mb-*.ops.example" in suffixes
        assert "ops.example" not in suffixes  # NOT full-zone
        # Secret is fresh random bytes (32) and survives a re-read.
        assert len(bytes.fromhex(minted.secret_hex)) == 32
        stored = keystore.get(minted.name)
        assert stored is not None
        assert stored.secret == bytes.fromhex(minted.secret_hex)
        assert minted.expires_at > 0

    def test_tight_scope_drops_wildcards_for_multi_tenant(
        self, keystore, config, challenges, monkeypatch
    ):
        """``DMP_TSIG_TIGHT_SCOPE=1`` (multi-tenant shared zone) drops
        the wildcard owner patterns so Alice's TSIG key can't
        overwrite Bob's records on the same zone. ``send_message``
        UPDATEs WILL be REFUSED in this mode — known limitation
        until per-sender prefix anchoring lands."""
        monkeypatch.setenv("DMP_TSIG_TIGHT_SCOPE", "1")
        pc = challenges.issue(config.node_hostname)
        body, _ = _signed_body(
            subject="alice@ops.example",
            challenge_hex=pc.challenge_hex,
            node=pc.node,
        )
        minted = mint_tsig_via_registration(
            keystore=keystore,
            challenges=challenges,
            config=config,
            body=body,
        )
        suffixes = set(minted.allowed_suffixes)
        assert "slot-*.mb-*.ops.example" not in suffixes
        assert "chunk-*-*.ops.example" not in suffixes
        assert "_dnsmesh-claim-*.ops.example" not in suffixes
        # Identity scope is still granted.
        assert any(s.startswith("id-") for s in suffixes)

    def test_identity_scope_uses_local_part_not_full_subject(
        self, keystore, config, challenges
    ):
        """Codex round-17 P1.1: ``dnsmesh identity publish`` derives
        the owner-name hash from the LOCAL PART (``cfg.username``),
        not the full subject. The minted scope must match — using
        sha256(full subject) here would mint a key that REFUSES
        the user's own identity / prekey publishes."""
        import hashlib as _hashlib

        pc = challenges.issue(config.node_hostname)
        body, _ = _signed_body(
            subject="alice@ops.example",
            challenge_hex=pc.challenge_hex,
            node=pc.node,
        )
        minted = mint_tsig_via_registration(
            keystore=keystore,
            challenges=challenges,
            config=config,
            body=body,
        )
        local_hash16 = _hashlib.sha256(b"alice").hexdigest()[:16]
        assert f"id-{local_hash16}.ops.example" in minted.allowed_suffixes
        # And the bad form (full-subject hash) must NOT be in scope.
        full_hash16 = _hashlib.sha256(b"alice@ops.example").hexdigest()[:16]
        assert f"id-{full_hash16}.ops.example" not in minted.allowed_suffixes

    def test_x25519_pub_extends_scope_to_mailbox(self, keystore, config, challenges):
        """When the registration body includes ``x25519_pub`` AND a
        valid ``x25519_pop``, the minted key gains
        ``mb-<hash12>.<zone>`` — the user's own mailbox alias."""
        import hashlib

        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.x25519 import (
            X25519PrivateKey,
        )

        from dmp.server.registration import build_x25519_pop

        # Real X25519 keypair so we can compute a valid PoP.
        x_priv_obj = X25519PrivateKey.generate()
        x_priv = x_priv_obj.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        x_pub = x_priv_obj.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        pc = challenges.issue(config.node_hostname)
        body, _ = _signed_body(
            subject="alice@ops.example",
            challenge_hex=pc.challenge_hex,
            node=pc.node,
        )
        body["x25519_pub"] = x_pub.hex()
        body["x25519_pop"] = build_x25519_pop(
            server_eph_pub=pc.server_x25519_eph_pub,
            x25519_priv=x_priv,
            challenge_hex=pc.challenge_hex,
            subject="alice@ops.example",
            claimed_x25519_pub=x_pub,
        ).hex()
        minted = mint_tsig_via_registration(
            keystore=keystore,
            challenges=challenges,
            config=config,
            body=body,
        )
        # Codex round-3 P1: registration's mailbox-hash convention is
        # ``hash12(recipient_id)`` = ``sha256(sha256(x_pub))[:12]`` so
        # it matches the actual ``mb-{hash12}.{zone}`` owner format.
        # The prior single-round formulation silently disagreed with
        # owner names; tight-scope mode would have rejected the
        # user's own mailbox writes.
        recipient_id = hashlib.sha256(x_pub).digest()
        mailbox_hash = hashlib.sha256(recipient_id).hexdigest()[:12]
        assert f"mb-{mailbox_hash}.ops.example" in minted.allowed_suffixes

    def test_long_local_part_rejected(self, keystore, config, challenges):
        """Codex round-6 P2: a local part too long for a 63-octet
        DNS label (after the ``-<spk8>`` suffix) must be rejected
        up-front, not silently produce a credential the DNS server
        will never honor."""
        long_local = "a" * 60  # 60 + 9 ('-' + 8 spk chars) > 63
        pc = challenges.issue(config.node_hostname)
        body, _ = _signed_body(
            subject=f"{long_local}@ops.example",
            challenge_hex=pc.challenge_hex,
            node=pc.node,
        )
        with pytest.raises(RegistrationError) as exc:
            mint_tsig_via_registration(
                keystore=keystore,
                challenges=challenges,
                config=config,
                body=body,
            )
        assert exc.value.http_status == 400

    def test_disabled_returns_404(self, keystore, challenges):
        cfg = RegistrationConfig(enabled=False, node_hostname="ops.example")
        body, _ = _signed_body(
            subject="alice@ops.example",
            challenge_hex="00" * 32,
            node="ops.example",
        )
        with pytest.raises(RegistrationError) as exc:
            mint_tsig_via_registration(
                keystore=keystore,
                challenges=challenges,
                config=cfg,
                body=body,
            )
        assert exc.value.http_status == 404

    def test_missing_hostname_returns_500(self, keystore, challenges):
        cfg = RegistrationConfig(enabled=True, node_hostname="")
        body, _ = _signed_body(
            subject="alice@ops.example",
            challenge_hex="00" * 32,
            node="ops.example",
        )
        with pytest.raises(RegistrationError) as exc:
            mint_tsig_via_registration(
                keystore=keystore,
                challenges=challenges,
                config=cfg,
                body=body,
            )
        assert exc.value.http_status == 500

    def test_unknown_challenge_rejected(self, keystore, config, challenges):
        body, _ = _signed_body(
            subject="alice@ops.example",
            challenge_hex="ab" * 32,  # never issued
            node=config.node_hostname,
        )
        with pytest.raises(RegistrationError):
            mint_tsig_via_registration(
                keystore=keystore,
                challenges=challenges,
                config=config,
                body=body,
            )

    def test_bad_signature_rejected(self, keystore, config, challenges):
        pc = challenges.issue(config.node_hostname)
        body, _ = _signed_body(
            subject="alice@ops.example",
            challenge_hex=pc.challenge_hex,
            node=pc.node,
        )
        # Flip a byte in the signature.
        sig = bytearray(bytes.fromhex(body["signature"]))
        sig[0] ^= 0xFF
        body["signature"] = sig.hex()
        with pytest.raises(SignatureInvalid):
            mint_tsig_via_registration(
                keystore=keystore,
                challenges=challenges,
                config=config,
                body=body,
            )

    def test_disallowed_domain_rejected(self, keystore, challenges):
        cfg = RegistrationConfig(
            enabled=True,
            node_hostname="ops.example",
            allowlist=("approved.example",),
        )
        pc = challenges.issue(cfg.node_hostname)
        body, _ = _signed_body(
            subject="alice@ops.example",
            challenge_hex=pc.challenge_hex,
            node=pc.node,
        )
        with pytest.raises(SubjectNotAllowed):
            mint_tsig_via_registration(
                keystore=keystore,
                challenges=challenges,
                config=cfg,
                body=body,
            )

    def test_scope_anchors_to_served_zone_not_node_hostname(self, keystore, challenges):
        """Codex P1 regression: when DMP_NODE_HOSTNAME is a host BENEATH
        the served zone (api.example.com under example.com), the minted
        TSIG scope must anchor to the served zone."""
        cfg = RegistrationConfig(
            enabled=True,
            node_hostname="api.example.com",
            served_zone="example.com",
            allowlist=(),
            expires_in_seconds=3600,
        )
        pc = challenges.issue(cfg.node_hostname)
        body, _ = _signed_body(
            subject="alice@example.com",
            challenge_hex=pc.challenge_hex,
            node=pc.node,
        )
        minted = mint_tsig_via_registration(
            keystore=keystore,
            challenges=challenges,
            config=cfg,
            body=body,
        )
        # Anchored under the served zone, not the hostname.
        assert minted.zone == "example.com"
        suffixes = set(minted.allowed_suffixes)
        assert any(s.startswith("id-") and s.endswith(".example.com") for s in suffixes)
        # Wildcards land under the served zone with the default
        # scope mode (single-user-per-zone).
        assert "slot-*.mb-*.example.com" in suffixes
        # And NEVER under the hostname.
        for suffix in suffixes:
            assert ".api.example.com" not in suffix
            assert "api.example.com" != suffix

    def test_served_zone_falls_back_to_node_hostname(self, keystore, challenges):
        """When served_zone isn't set explicitly we still want a
        usable scope — back-compat for single-host deployments where
        node_hostname IS the zone apex."""
        cfg = RegistrationConfig(
            enabled=True,
            node_hostname="solo.example",
            served_zone="",
            allowlist=(),
        )
        pc = challenges.issue(cfg.node_hostname)
        body, _ = _signed_body(
            subject="alice@solo.example",
            challenge_hex=pc.challenge_hex,
            node=pc.node,
        )
        minted = mint_tsig_via_registration(
            keystore=keystore,
            challenges=challenges,
            config=cfg,
            body=body,
        )
        assert minted.zone == "solo.example"

    def test_same_spk_remint_rotates_secret(self, keystore, config, challenges):
        """Re-registration with the SAME spk replaces the secret. A
        user who lost their TSIG key can re-mint by signing a fresh
        challenge with the same Ed25519 key they registered with."""
        priv = Ed25519PrivateKey.generate()
        pub = priv.public_key().public_bytes_raw()

        def _mint() -> any:
            pc = challenges.issue(config.node_hostname)
            payload = _build_signing_payload(
                pc.challenge_hex, "alice@ops.example", pc.node
            )
            body = {
                "subject": "alice@ops.example",
                "ed25519_spk": pub.hex(),
                "challenge": pc.challenge_hex,
                "signature": priv.sign(payload).hex(),
            }
            return mint_tsig_via_registration(
                keystore=keystore,
                challenges=challenges,
                config=config,
                body=body,
            )

        first = _mint()
        second = _mint()
        # Same key name (spk-derived), fresh secret bytes.
        assert first.name == second.name
        assert first.secret_hex != second.secret_hex

    def test_different_spk_for_same_subject_rejected(
        self, keystore, config, challenges
    ):
        """Anti-takeover (codex round-3 P1): a second registrant for
        the same subject under a DIFFERENT spk must be rejected. The
        legitimate user has to revoke first to re-register with a new
        identity. Without this check anyone who could complete the
        Ed25519 challenge for ``alice@ops.example`` got a parallel
        TSIG key with full publish authority on Alice's records."""
        # First registrant succeeds.
        pc1 = challenges.issue(config.node_hostname)
        body1, _ = _signed_body(
            subject="alice@ops.example",
            challenge_hex=pc1.challenge_hex,
            node=pc1.node,
        )
        mint_tsig_via_registration(
            keystore=keystore,
            challenges=challenges,
            config=config,
            body=body1,
        )
        # Second registrant — different keypair, same subject — bounced.
        pc2 = challenges.issue(config.node_hostname)
        body2, _ = _signed_body(
            subject="alice@ops.example",
            challenge_hex=pc2.challenge_hex,
            node=pc2.node,
        )
        from dmp.server.registration import SubjectAlreadyOwned

        with pytest.raises(SubjectAlreadyOwned):
            mint_tsig_via_registration(
                keystore=keystore,
                challenges=challenges,
                config=config,
                body=body2,
            )

    def test_revoked_subject_can_re_register_with_new_spk(
        self, keystore, config, challenges
    ):
        """The escape hatch: revoke the existing key and the same
        subject becomes available for a fresh registration under a
        different spk. Lets a user who lost their original Ed25519
        key recover by going through admin-side revocation."""
        # First mint, then revoke.
        pc1 = challenges.issue(config.node_hostname)
        body1, _ = _signed_body(
            subject="alice@ops.example",
            challenge_hex=pc1.challenge_hex,
            node=pc1.node,
        )
        first = mint_tsig_via_registration(
            keystore=keystore,
            challenges=challenges,
            config=config,
            body=body1,
        )
        keystore.revoke(first.name)
        # Now a different spk can register for the same subject.
        pc2 = challenges.issue(config.node_hostname)
        body2, _ = _signed_body(
            subject="alice@ops.example",
            challenge_hex=pc2.challenge_hex,
            node=pc2.node,
        )
        second = mint_tsig_via_registration(
            keystore=keystore,
            challenges=challenges,
            config=config,
            body=body2,
        )
        assert second.name != first.name


class TestX25519ProofOfPossession:
    # The forgery surface is: an attacker reads a victim's published
    # ``x25519_pub`` from their identity record, registers under their
    # OWN subject + Ed25519 key but claims the victim's ``x25519_pub``,
    # and the server mints a TSIG key scoped to
    # ``mb-{hash12(victim_x25519_pub)}.{zone}``. Under
    # DMP_TSIG_TIGHT_SCOPE that's a direct write into the victim's
    # mailbox; under loose scope the wildcards already grant the same
    # but the literal mailbox suffix is privilege the attacker shouldn't
    # have. The PoP check requires the registrant to prove possession
    # of the X25519 private half before that scope is granted.

    def _real_x25519_keypair(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.x25519 import (
            X25519PrivateKey,
        )

        priv_obj = X25519PrivateKey.generate()
        priv = priv_obj.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub = priv_obj.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return priv, pub

    def _build_pop(self, pc, *, x_priv, x_pub, subject):
        from dmp.server.registration import build_x25519_pop

        return build_x25519_pop(
            server_eph_pub=pc.server_x25519_eph_pub,
            x25519_priv=x_priv,
            challenge_hex=pc.challenge_hex,
            subject=subject,
            claimed_x25519_pub=x_pub,
        ).hex()

    def test_valid_pop_grants_mailbox_scope(self, keystore, config, challenges):
        x_priv, x_pub = self._real_x25519_keypair()
        pc = challenges.issue(config.node_hostname)
        body, _ = _signed_body(
            subject="alice@ops.example",
            challenge_hex=pc.challenge_hex,
            node=pc.node,
        )
        body["x25519_pub"] = x_pub.hex()
        body["x25519_pop"] = self._build_pop(
            pc, x_priv=x_priv, x_pub=x_pub, subject="alice@ops.example"
        )
        minted = mint_tsig_via_registration(
            keystore=keystore,
            challenges=challenges,
            config=config,
            body=body,
        )
        # Confirms the literal ``mb-{hash12}.{zone}`` suffix lands.
        import hashlib

        recipient_id = hashlib.sha256(x_pub).digest()
        mailbox_hash = hashlib.sha256(recipient_id).hexdigest()[:12]
        assert f"mb-{mailbox_hash}.ops.example" in minted.allowed_suffixes

    def test_pop_mismatched_pub_refused(self, keystore, config, challenges):
        # Attacker holds x_priv_attacker but claims x_pub_victim. The
        # PoP they can compute is over their own keypair; the server
        # tries to verify against the CLAIMED victim pub and the DH
        # shared-secret won't match.
        attacker_priv, attacker_pub = self._real_x25519_keypair()
        _, victim_pub = self._real_x25519_keypair()

        pc = challenges.issue(config.node_hostname)
        body, _ = _signed_body(
            subject="attacker@ops.example",
            challenge_hex=pc.challenge_hex,
            node=pc.node,
        )
        body["x25519_pub"] = victim_pub.hex()
        # Attacker computes a "PoP" with their own private key but
        # claims the victim's pubkey. Server's DH against the claimed
        # pub yields a different shared secret, HMAC fails.
        body["x25519_pop"] = self._build_pop(
            pc,
            x_priv=attacker_priv,
            x_pub=attacker_pub,
            subject="attacker@ops.example",
        )
        with pytest.raises(SignatureInvalid):
            mint_tsig_via_registration(
                keystore=keystore,
                challenges=challenges,
                config=config,
                body=body,
            )

    def test_pop_garbage_bytes_refused(self, keystore, config, challenges):
        _, x_pub = self._real_x25519_keypair()
        pc = challenges.issue(config.node_hostname)
        body, _ = _signed_body(
            subject="alice@ops.example",
            challenge_hex=pc.challenge_hex,
            node=pc.node,
        )
        body["x25519_pub"] = x_pub.hex()
        body["x25519_pop"] = "00" * 32  # 32 bytes of zeros, not a valid HMAC
        with pytest.raises(SignatureInvalid):
            mint_tsig_via_registration(
                keystore=keystore,
                challenges=challenges,
                config=config,
                body=body,
            )

    def test_pop_bound_to_subject(self, keystore, config, challenges):
        # Attacker captured a victim's valid (challenge, pop, subject)
        # tuple from a real registration, then tries to replay it
        # under their own subject. The server's HMAC check binds the
        # subject into the message so the attacker's substitution
        # invalidates the proof.
        x_priv, x_pub = self._real_x25519_keypair()
        pc = challenges.issue(config.node_hostname)
        # Victim built a pop for THEIR subject.
        victim_pop = self._build_pop(
            pc, x_priv=x_priv, x_pub=x_pub, subject="alice@ops.example"
        )
        # Attacker tries to use it under a different subject.
        body, _ = _signed_body(
            subject="mallory@ops.example",
            challenge_hex=pc.challenge_hex,
            node=pc.node,
        )
        body["x25519_pub"] = x_pub.hex()
        body["x25519_pop"] = victim_pop
        with pytest.raises(SignatureInvalid):
            mint_tsig_via_registration(
                keystore=keystore,
                challenges=challenges,
                config=config,
                body=body,
            )

    def test_pop_replay_across_challenges_refused(self, keystore, config, challenges):
        # An attacker captures a valid (challenge_A, x25519_pub, pop_A)
        # tuple. They can't replay pop_A against a fresh challenge_B
        # because the server's ephemeral X25519 private differs per
        # challenge — the DH shared secret won't match.
        x_priv, x_pub = self._real_x25519_keypair()

        # Issue and immediately consume challenge A so we have a valid
        # pop bound to A's ephemeral key, then issue challenge B.
        pc_a = challenges.issue(config.node_hostname)
        pop_a = self._build_pop(
            pc_a, x_priv=x_priv, x_pub=x_pub, subject="alice@ops.example"
        )
        # Consume A so the next confirm uses challenge B (a confirm
        # only consumes its OWN challenge — fresh issue gives the
        # attacker a different nonce).
        pc_b = challenges.issue(config.node_hostname)
        body, _ = _signed_body(
            subject="alice@ops.example",
            challenge_hex=pc_b.challenge_hex,
            node=pc_b.node,
        )
        body["x25519_pub"] = x_pub.hex()
        body["x25519_pop"] = pop_a  # pop bound to challenge A, not B
        with pytest.raises(SignatureInvalid):
            mint_tsig_via_registration(
                keystore=keystore,
                challenges=challenges,
                config=config,
                body=body,
            )

    def test_legacy_client_no_pop_drops_pubkey_silently(
        self, keystore, config, challenges
    ):
        # Legacy clients that POST ``x25519_pub`` without
        # ``x25519_pop`` keep working but lose the literal
        # ``mb-{hash}.{zone}`` suffix. Identity / prekey / own-claim
        # literal suffixes are unaffected, and the wildcard scopes
        # in loose mode still apply.
        _, x_pub = self._real_x25519_keypair()
        pc = challenges.issue(config.node_hostname)
        body, _ = _signed_body(
            subject="alice@ops.example",
            challenge_hex=pc.challenge_hex,
            node=pc.node,
        )
        body["x25519_pub"] = x_pub.hex()
        # Deliberately omit x25519_pop.
        minted = mint_tsig_via_registration(
            keystore=keystore,
            challenges=challenges,
            config=config,
            body=body,
        )
        # Wildcard scope still present.
        assert any("slot-*.mb-*" in s for s in minted.allowed_suffixes)
        # Literal mailbox suffix NOT present (since the pubkey was
        # dropped from scope derivation without proof).
        import hashlib

        recipient_id = hashlib.sha256(x_pub).digest()
        mailbox_hash = hashlib.sha256(recipient_id).hexdigest()[:12]
        assert f"mb-{mailbox_hash}.ops.example" not in minted.allowed_suffixes


class TestHttpEndpoint:
    """End-to-end: boot DMPHttpApi with a keystore, run the full
    challenge/confirm dance, assert the minted key works against
    DMPDnsServer's UPDATE handler with the keystore-built keyring."""

    def test_full_flow_mints_usable_tsig_key(self, tmp_path):
        import base64
        import json
        import socket
        import time as _time
        import urllib.request

        import dns.message
        import dns.name
        import dns.query
        import dns.rcode
        import dns.tsigkeyring
        import dns.update

        from dmp.network.memory import InMemoryDNSStore
        from dmp.server.dns_server import DMPDnsServer
        from dmp.server.http_api import DMPHttpApi
        from dmp.server.tokens import TokenStore

        record_store = InMemoryDNSStore()
        keystore = TSIGKeyStore(str(tmp_path / "tsig.db"))
        try:
            token_store = TokenStore(str(tmp_path / "tokens.db"))

            # Bind two free ports — HTTP for registration, UDP for DNS.
            def _free():
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.bind(("127.0.0.1", 0))
                p = s.getsockname()[1]
                s.close()
                return p

            http_port = _free()
            dns_port = _free()

            cfg = RegistrationConfig(
                enabled=True,
                node_hostname="ops.example",
                allowlist=(),  # no domain restriction
                expires_in_seconds=3600,
            )
            api = DMPHttpApi(
                record_store,
                host="127.0.0.1",
                port=http_port,
                auth_mode="multi-tenant",
                token_store=token_store,
                registration_config=cfg,
                tsig_keystore=keystore,
            )
            api.start()
            try:
                # Step 1: GET /challenge.
                with urllib.request.urlopen(
                    f"http://127.0.0.1:{http_port}/v1/registration/challenge",
                    timeout=2,
                ) as resp:
                    challenge = json.loads(resp.read())
                # Step 2: sign challenge|subject|node + version.
                priv = Ed25519PrivateKey.generate()
                pub = priv.public_key().public_bytes_raw()
                subject = "alice@ops.example"
                payload = _build_signing_payload(
                    challenge["challenge"], subject, challenge["node"]
                )
                sig = priv.sign(payload)
                # Step 3: POST /tsig-confirm.
                req = urllib.request.Request(
                    f"http://127.0.0.1:{http_port}/v1/registration/tsig-confirm",
                    data=json.dumps(
                        {
                            "subject": subject,
                            "ed25519_spk": pub.hex(),
                            "challenge": challenge["challenge"],
                            "signature": sig.hex(),
                        }
                    ).encode("utf-8"),
                    headers={"content-type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=2) as resp:
                    minted = json.loads(resp.read())
            finally:
                api.stop()

            # Now boot a DNS server with the keystore-built keyring +
            # authorizer and use the minted TSIG key to publish a
            # record under the user's allowed scope.
            dns_server = DMPDnsServer(
                record_store,
                host="127.0.0.1",
                port=dns_port,
                writer=record_store,
                tsig_keyring=keystore.build_keyring(),
                allowed_zones=("ops.example",),
                update_authorizer=keystore.build_authorizer(),
            )
            with dns_server:
                client_keyring = dns.tsigkeyring.from_text(
                    {
                        minted["tsig_key_name"]: base64.b64encode(
                            bytes.fromhex(minted["tsig_secret_hex"])
                        ).decode("ascii")
                    }
                )
                # Use an actual DMP record owner — identity at
                # ``id-<hash16>.<zone>``. The hash is sha256 of the
                # LOCAL PART (matches what ``dnsmesh identity publish``
                # writes — codex round-17 P1.1 fix).
                import hashlib as _hashlib

                local_part = subject.split("@", 1)[0]
                username_hash = _hashlib.sha256(local_part.encode("utf-8")).hexdigest()[
                    :16
                ]
                identity_owner = f"id-{username_hash}.ops.example."
                upd = dns.update.UpdateMessage("ops.example")
                upd.add(
                    dns.name.from_text(identity_owner),
                    300,
                    "TXT",
                    '"v=dmp1;t=identity"',
                )
                upd.use_tsig(
                    client_keyring,
                    keyname=dns.name.from_text(minted["tsig_key_name"]),
                )
                response = dns.query.udp(upd, "127.0.0.1", port=dns_port, timeout=2.0)
            assert response.rcode() == dns.rcode.NOERROR
            assert record_store.query_txt_record(identity_owner.rstrip(".")) == [
                "v=dmp1;t=identity"
            ]
        finally:
            keystore.close()

    def test_endpoint_404s_without_keystore(self, tmp_path):
        """A node that didn't wire a keystore still answers
        /v1/registration/confirm but returns 404 on /tsig-confirm —
        no quiet downgrade."""
        import json
        import socket
        import urllib.error
        import urllib.request

        from dmp.network.memory import InMemoryDNSStore
        from dmp.server.http_api import DMPHttpApi
        from dmp.server.tokens import TokenStore

        record_store = InMemoryDNSStore()
        token_store = TokenStore(str(tmp_path / "tokens.db"))
        # TCP socket — DMPHttpApi binds TCP, and the kernel hands out
        # free ports per-protocol. Using SOCK_DGRAM here returned a
        # UDP-free port that wasn't necessarily TCP-free, causing
        # ``OSError: [Errno 98] Address already in use`` on busy CI
        # runners (py3.11/3.12 hit it on PR #41's matrix).
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()

        cfg = RegistrationConfig(
            enabled=True,
            node_hostname="ops.example",
            allowlist=(),
        )
        api = DMPHttpApi(
            record_store,
            host="127.0.0.1",
            port=port,
            auth_mode="multi-tenant",
            token_store=token_store,
            registration_config=cfg,
            tsig_keystore=None,
        )
        api.start()
        try:
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/v1/registration/tsig-confirm",
                data=b"{}",
                headers={"content-type": "application/json"},
                method="POST",
            )
            with pytest.raises(urllib.error.HTTPError) as exc:
                urllib.request.urlopen(req, timeout=2)
            assert exc.value.code == 404
        finally:
            api.stop()
