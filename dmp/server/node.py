"""DMPNode — orchestrator that wires storage, DNS, HTTP, and cleanup.

Running a DMP node is usually just:

    from dmp.server.node import DMPNode

    node = DMPNode.from_env()
    node.start()
    node.wait()   # blocks until SIGTERM/SIGINT

Or as a module entrypoint:

    python -m dmp.server.node

Environment variables (all optional, sensible defaults for dev):

    DMP_DB_PATH           path to sqlite db                default: /var/lib/dmp/dmp.db
    DMP_DNS_HOST          bind host for the UDP DNS server  default: 0.0.0.0
    DMP_DNS_PORT          UDP port for DNS queries          default: 5353
    DMP_DNS_TTL           TTL seconds advertised in DNS     default: 60
    DMP_HTTP_HOST         bind host for HTTP API            default: 0.0.0.0
    DMP_HTTP_PORT         TCP port for HTTP API             default: 8053
    DMP_HTTP_TOKEN        bearer token for /v1/*            default: none (open)
    DMP_CLEANUP_INTERVAL  seconds between cleanup sweeps    default: 60
    DMP_LOG_LEVEL         python logging level              default: INFO

Port 53 is privileged on Linux. In a container, publish with
`-p 53:5353/udp` or run with CAP_NET_BIND_SERVICE.
"""

from __future__ import annotations

import logging
import os
import signal
import threading
from dataclasses import dataclass
from typing import Optional

from dmp.server.cleanup import CleanupWorker
from dmp.server.dns_server import DMPDnsServer
from dmp.server.http_api import DMPHttpApi
from dmp.storage.sqlite_store import SqliteMailboxStore


log = logging.getLogger(__name__)


@dataclass
class DMPNodeConfig:
    db_path: str = "/var/lib/dmp/dmp.db"
    dns_host: str = "0.0.0.0"
    dns_port: int = 5353
    dns_ttl: int = 60
    http_host: str = "0.0.0.0"
    http_port: int = 8053
    http_token: Optional[str] = None
    cleanup_interval: float = 60.0
    log_level: str = "INFO"

    @classmethod
    def from_env(cls) -> "DMPNodeConfig":
        return cls(
            db_path=os.environ.get("DMP_DB_PATH", cls.db_path),
            dns_host=os.environ.get("DMP_DNS_HOST", cls.dns_host),
            dns_port=int(os.environ.get("DMP_DNS_PORT", cls.dns_port)),
            dns_ttl=int(os.environ.get("DMP_DNS_TTL", cls.dns_ttl)),
            http_host=os.environ.get("DMP_HTTP_HOST", cls.http_host),
            http_port=int(os.environ.get("DMP_HTTP_PORT", cls.http_port)),
            http_token=os.environ.get("DMP_HTTP_TOKEN") or None,
            cleanup_interval=float(
                os.environ.get("DMP_CLEANUP_INTERVAL", cls.cleanup_interval)
            ),
            log_level=os.environ.get("DMP_LOG_LEVEL", cls.log_level),
        )


class DMPNode:
    """A full DMP node: sqlite store + DNS server + HTTP API + cleanup."""

    def __init__(self, config: Optional[DMPNodeConfig] = None):
        self.config = config or DMPNodeConfig()
        self.store: Optional[SqliteMailboxStore] = None
        self.dns: Optional[DMPDnsServer] = None
        self.http: Optional[DMPHttpApi] = None
        self.cleanup: Optional[CleanupWorker] = None
        self._stopped = threading.Event()

    @classmethod
    def from_env(cls) -> "DMPNode":
        return cls(DMPNodeConfig.from_env())

    def start(self) -> None:
        logging.basicConfig(
            level=getattr(logging, self.config.log_level.upper(), logging.INFO),
            format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        )

        self._ensure_db_parent_exists()

        self.store = SqliteMailboxStore(self.config.db_path)
        self.dns = DMPDnsServer(
            self.store,
            host=self.config.dns_host,
            port=self.config.dns_port,
            ttl=self.config.dns_ttl,
        )
        self.http = DMPHttpApi(
            self.store,
            host=self.config.http_host,
            port=self.config.http_port,
            bearer_token=self.config.http_token,
        )
        self.cleanup = CleanupWorker(
            self.store.cleanup_expired,
            interval_seconds=self.config.cleanup_interval,
        )

        self.dns.start()
        self.http.start()
        self.cleanup.start()
        log.info(
            "DMP node up: dns=%s:%d/udp http=%s:%d db=%s",
            self.config.dns_host,
            self.dns.port,
            self.config.http_host,
            self.http.port,
            self.config.db_path,
        )

    def stop(self) -> None:
        log.info("DMP node shutting down")
        if self.cleanup:
            self.cleanup.stop()
        if self.http:
            self.http.stop()
        if self.dns:
            self.dns.stop()
        if self.store:
            self.store.close()
        self._stopped.set()

    def wait(self) -> None:
        """Block until stop() is called or a signal arrives."""
        self._install_signal_handlers()
        try:
            self._stopped.wait()
        except KeyboardInterrupt:
            self.stop()

    def _ensure_db_parent_exists(self) -> None:
        parent = os.path.dirname(self.config.db_path) or "."
        os.makedirs(parent, exist_ok=True)

    def _install_signal_handlers(self) -> None:
        def _handle(signum, frame):
            log.info("received signal %s", signum)
            self.stop()

        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(sig, _handle)
            except ValueError:
                # Not in main thread — skip.
                pass


def main() -> None:
    node = DMPNode.from_env()
    node.start()
    node.wait()


if __name__ == "__main__":
    main()
