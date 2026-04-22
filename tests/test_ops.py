"""Tests for the ops-hardening surface: metrics, rate limiting, JSON logs."""

import json
import logging
import socket
import time

import dns.message
import dns.query
import dns.rdatatype
import pytest
import requests

from dmp.network.memory import InMemoryDNSStore
from dmp.server.dns_server import DMPDnsServer
from dmp.server.http_api import DMPHttpApi
from dmp.server.logging_config import JsonFormatter, configure_logging
from dmp.server.metrics import REGISTRY, MetricsRegistry
from dmp.server.rate_limit import RateLimit, TokenBucketLimiter


def _free_port(kind=socket.SOCK_STREAM) -> int:
    s = socket.socket(socket.AF_INET, kind)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# ----------------------------- rate limit -----------------------------------


class TestTokenBucketLimiter:
    def test_disabled_always_allows(self):
        limiter = TokenBucketLimiter(RateLimit.disabled())
        for _ in range(100):
            assert limiter.allow("1.2.3.4")

    def test_burst_and_refill(self):
        limiter = TokenBucketLimiter(RateLimit(rate_per_second=10.0, burst=3.0))
        # First three succeed (burst = 3).
        assert limiter.allow("10.0.0.1")
        assert limiter.allow("10.0.0.1")
        assert limiter.allow("10.0.0.1")
        # Fourth rejected.
        assert not limiter.allow("10.0.0.1")
        # Wait for a refill and try again.
        time.sleep(0.2)  # 0.2s × 10/s = 2 tokens refilled.
        assert limiter.allow("10.0.0.1")

    def test_per_key_isolation(self):
        limiter = TokenBucketLimiter(RateLimit(rate_per_second=1.0, burst=1.0))
        assert limiter.allow("A")
        assert not limiter.allow("A")
        assert limiter.allow("B")  # B has its own bucket.

    def test_lru_eviction_caps_memory(self):
        limiter = TokenBucketLimiter(
            RateLimit(rate_per_second=1.0, burst=1.0), max_tracked=5
        )
        for i in range(10):
            limiter.allow(f"ip-{i}")
        assert limiter.size() <= 5


# ----------------------------- metrics --------------------------------------


class TestMetricsRegistry:
    def test_counter_accumulates(self):
        r = MetricsRegistry()
        r.counter("foo_total", labels={"a": "1"})
        r.counter("foo_total", labels={"a": "1"}, amount=3.0)
        text = r.render()
        assert 'foo_total{a="1"} 4.0' in text

    def test_gauge_sets_absolute_value(self):
        r = MetricsRegistry()
        r.gauge("bar", 1.0)
        r.gauge("bar", 42.0)
        assert "bar 42.0" in r.render()

    def test_lazy_gauge_queried_at_render(self):
        r = MetricsRegistry()
        box = {"n": 7}
        r.register_lazy_gauge("live", lambda: box["n"], help_text="live count")
        assert "live 7.0" in r.render()
        box["n"] = 100
        assert "live 100.0" in r.render()

    def test_invalid_label_name_rejected(self):
        r = MetricsRegistry()
        with pytest.raises(ValueError):
            r.counter("x_total", labels={"bad label": "1"})

    def test_render_is_prometheus_text_format(self):
        r = MetricsRegistry()
        r.counter("x_total", help_text="x help", labels={"k": "v"})
        text = r.render()
        assert "# HELP x_total x help" in text
        assert "# TYPE x_total counter" in text


# ----------------------------- JSON logs ------------------------------------


class TestJsonLogs:
    def test_formatter_emits_json_line(self):
        formatter = JsonFormatter()
        record = logging.LogRecord(
            name="demo",
            level=logging.INFO,
            pathname=__file__,
            lineno=1,
            msg="hello %s",
            args=("world",),
            exc_info=None,
        )
        record.request_id = "abc"
        out = formatter.format(record)
        parsed = json.loads(out)
        assert parsed["level"] == "INFO"
        assert parsed["logger"] == "demo"
        assert parsed["msg"] == "hello world"
        assert parsed["request_id"] == "abc"

    def test_configure_logging_is_idempotent(self):
        configure_logging("INFO", "text")
        configure_logging("INFO", "json")
        root = logging.getLogger()
        # Second call should have replaced, not appended.
        assert len(root.handlers) == 1


# ----------------------------- HTTP integration -----------------------------


class TestHttpOps:
    @pytest.fixture
    def api(self):
        store = InMemoryDNSStore()
        a = DMPHttpApi(store, host="127.0.0.1", port=_free_port())
        a.start()
        try:
            yield a, store
        finally:
            a.stop()

    def test_metrics_endpoint_exposes_counters(self, api):
        """When a bearer token is configured, /metrics requires it too
        (not just /v1/records/*). This fixture runs with no token set,
        so /metrics stays open — see the "requires_token" /
        "open_when_no_token" tests below for the two configurations.
        """
        server, store = api
        base = f"http://127.0.0.1:{server.port}"
        # Generate one successful POST to bump the counter.
        requests.post(
            f"{base}/v1/records/x.mesh.test",
            json={"value": "v", "ttl": 60},
            timeout=2,
        )
        r = requests.get(f"{base}/metrics", timeout=2)
        assert r.status_code == 200
        assert "dmp_http_requests_total" in r.text
        assert 'method="POST"' in r.text

    def test_metrics_endpoint_requires_token_when_configured(self):
        """With a bearer token set, /metrics refuses unauthenticated GETs.

        Metrics leak publish rate, rate-limit hits, per-operation error
        counters — for a privacy-oriented protocol that's an activity
        indicator the operator does not want open to the world.
        """
        store = InMemoryDNSStore()
        a = DMPHttpApi(
            store,
            host="127.0.0.1",
            port=_free_port(),
            bearer_token="s3cret-token",
        )
        a.start()
        try:
            base = f"http://127.0.0.1:{a.port}"

            # No token → 401.
            r = requests.get(f"{base}/metrics", timeout=2)
            assert r.status_code == 401

            # Wrong token → 401.
            r = requests.get(
                f"{base}/metrics",
                headers={"Authorization": "Bearer wrong-token"},
                timeout=2,
            )
            assert r.status_code == 401

            # Correct token → 200 with prometheus body.
            r = requests.get(
                f"{base}/metrics",
                headers={"Authorization": "Bearer s3cret-token"},
                timeout=2,
            )
            assert r.status_code == 200
            assert "dmp_http_requests_total" in r.text
        finally:
            a.stop()

    def test_metrics_endpoint_open_when_no_token(self):
        """Dev path: no bearer_token configured → /metrics is reachable
        without auth. The server logs a startup WARNING so this is not
        silently shipped to prod — see test_warning_logged_when_no_token
        below."""
        store = InMemoryDNSStore()
        a = DMPHttpApi(store, host="127.0.0.1", port=_free_port())
        a.start()
        try:
            r = requests.get(f"http://127.0.0.1:{a.port}/metrics", timeout=2)
            assert r.status_code == 200
            assert "dmp_http_requests_total" in r.text or r.text == ""
        finally:
            a.stop()

    def test_warning_logged_when_no_token(self, caplog):
        """When no bearer_token is configured, DMPHttpApi.start() MUST
        log a WARNING naming DMP_HTTP_TOKEN so an operator can't
        silently deploy an unauthenticated metrics endpoint to prod."""
        store = InMemoryDNSStore()
        a = DMPHttpApi(store, host="127.0.0.1", port=_free_port())
        with caplog.at_level(logging.WARNING, logger="dmp.server.http_api"):
            a.start()
            try:
                pass
            finally:
                a.stop()
        assert any(
            "metrics endpoint unauthenticated" in r.message for r in caplog.records
        )
        assert any("DMP_HTTP_TOKEN" in r.message for r in caplog.records)

    def test_no_warning_when_token_configured(self, caplog):
        """When a bearer_token IS configured, start() MUST NOT log the
        'metrics endpoint unauthenticated' warning — it would be
        misleading noise."""
        store = InMemoryDNSStore()
        a = DMPHttpApi(store, host="127.0.0.1", port=_free_port(), bearer_token="x")
        with caplog.at_level(logging.WARNING, logger="dmp.server.http_api"):
            a.start()
            try:
                pass
            finally:
                a.stop()
        assert not any(
            "metrics endpoint unauthenticated" in r.message for r in caplog.records
        )

    def test_health_degrades_on_broken_store(self):
        class BrokenStore(InMemoryDNSStore):
            def query_txt_record(self, name):
                raise RuntimeError("sqlite on fire")

        store = BrokenStore()
        a = DMPHttpApi(store, host="127.0.0.1", port=_free_port())
        a.start()
        try:
            r = requests.get(f"http://127.0.0.1:{a.port}/health", timeout=2)
            assert r.status_code == 503
            assert r.json()["status"] == "degraded"
        finally:
            a.stop()

    def test_rate_limit_returns_429(self):
        store = InMemoryDNSStore()
        a = DMPHttpApi(
            store,
            host="127.0.0.1",
            port=_free_port(),
            rate_limit=RateLimit(rate_per_second=0.1, burst=1.0),
        )
        a.start()
        try:
            base = f"http://127.0.0.1:{a.port}"
            r1 = requests.post(
                f"{base}/v1/records/x.mesh.test",
                json={"value": "v", "ttl": 60},
                timeout=2,
            )
            r2 = requests.post(
                f"{base}/v1/records/x.mesh.test",
                json={"value": "v", "ttl": 60},
                timeout=2,
            )
            assert r1.status_code == 201
            assert r2.status_code == 429
        finally:
            a.stop()


class TestBoundedConcurrency:
    def test_http_drops_connection_past_ceiling(self):
        """When the concurrency ceiling is hit, new TCP connections are
        closed immediately instead of spawning more handler threads.

        The raw ThreadingMixIn would create threads without bound — a
        socket flood would exhaust memory before the rate limiter engaged.
        The bounded pool caps simultaneous handlers.
        """
        import threading
        import requests

        # A handler that blocks until the test releases it. Max concurrency
        # of 1 means the second connection should be dropped.
        blocker = threading.Event()

        # Piggy-back a custom store whose query blocks the /health handler.
        class SlowStore(InMemoryDNSStore):
            def query_txt_record(self, name):
                if name == "__dmp_health_probe__":
                    blocker.wait(timeout=2.0)
                return super().query_txt_record(name)

        store = SlowStore()
        api = DMPHttpApi(store, host="127.0.0.1", port=_free_port(), max_concurrency=1)
        api.start()
        base = f"http://127.0.0.1:{api.port}"
        try:
            # First request occupies the single slot.
            first = threading.Thread(
                target=lambda: requests.get(f"{base}/health", timeout=5),
                daemon=True,
            )
            first.start()
            time.sleep(0.1)  # let the first handler pin the slot

            # Second request should be dropped (connection closed).
            # requests raises ConnectionError when the peer closes before
            # sending bytes.
            dropped = False
            try:
                requests.get(f"{base}/health", timeout=1)
            except requests.exceptions.ConnectionError:
                dropped = True
            except Exception:
                dropped = True
            assert dropped, "expected the second connection to be dropped"

            # Release the first handler.
            blocker.set()
            first.join(timeout=3.0)
        finally:
            blocker.set()
            api.stop()


class TestDnsRateLimit:
    def test_dns_rate_limit_drops_query(self):
        import dns.exception

        store = InMemoryDNSStore()
        store.publish_txt_record("x.mesh.test", "v=dmp1;t=chunk")
        port = _free_port(socket.SOCK_DGRAM)
        server = DMPDnsServer(
            store,
            host="127.0.0.1",
            port=port,
            rate_limit=RateLimit(rate_per_second=0.1, burst=1.0),
        )
        server.start()
        try:
            q = dns.message.make_query("x.mesh.test", dns.rdatatype.TXT)
            r1 = dns.query.udp(q, "127.0.0.1", port=port, timeout=2.0)
            assert r1.rcode() == 0
            # Second query hits the limit — we drop silently on UDP. The
            # client sees either a timeout or a parse error on whatever
            # packet-soup arrives. Either way, no valid response.
            with pytest.raises((dns.exception.Timeout, dns.exception.DNSException)):
                dns.query.udp(q, "127.0.0.1", port=port, timeout=1.0)
        finally:
            server.stop()
