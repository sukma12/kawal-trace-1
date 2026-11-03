"""Read-only MySQL/MariaDB and Microsoft SQL Server audit-source connector.

The administrator must enable/configure a real audit table or view and create a
least-privilege read-only account. This module never accepts arbitrary SQL. Table
and column names are strict identifiers; values are always bound parameters.
"""
from __future__ import annotations

import hashlib
import importlib
import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

from .detection import normalize_server_event

IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_$]{0,127}$")
SUPPORTED_ENGINES = {"mysql", "mariadb", "sqlserver"}
MAX_LIMIT = 500


class DatabaseAuditError(ValueError):
    """Invalid source, unsupported driver, TLS, or database audit query failure."""


@dataclass(frozen=True)
class DatabaseAuditConfig:
    engine: str
    host: str
    database: str
    username: str
    source_table: str
    timestamp_column: str = "event_time"
    event_type_column: str = "event_type"
    host_column: str = "host_id"
    source_column: str = "source"
    actor_column: str = "actor"
    message_column: str = "message"
    event_id_column: str = "event_id"
    schema: str = "dbo"
    port: int | None = None
    tls_ca_file: str = ""
    timeout_seconds: int = 8

    def validated(self) -> "DatabaseAuditConfig":
        engine = str(self.engine or "").strip().lower()
        if engine not in SUPPORTED_ENGINES:
            raise DatabaseAuditError("Engine audit database harus mysql, mariadb, atau sqlserver.")
        host = str(self.host or "").strip()
        if not host or len(host) > 253 or any(ch in host for ch in "/\\@?#;$`|&<>\r\n\t") or any(ord(ch) < 33 for ch in host):
            raise DatabaseAuditError("Hostname database tidak valid.")
        if not str(self.username or "").strip() or len(self.username) > 128:
            raise DatabaseAuditError("Username database audit wajib diisi.")
        if not str(self.database or "").strip() or len(self.database) > 128:
            raise DatabaseAuditError("Nama database wajib diisi.")
        try:
            port = int(self.port or (1433 if engine == "sqlserver" else 3306))
            timeout = int(self.timeout_seconds)
        except (TypeError, ValueError) as exc:
            raise DatabaseAuditError("Port/timeout database harus berupa bilangan bulat.") from exc
        if not 1 <= port <= 65535 or not 1 <= timeout <= 30:
            raise DatabaseAuditError("Port harus 1–65535 dan timeout 1–30 detik.")
        for name in ("source_table", "timestamp_column", "event_type_column", "host_column", "source_column", "actor_column", "message_column"):
            value = str(getattr(self, name) or "")
            parts = value.split(".") if name == "source_table" else [value]
            if not parts or any(not IDENTIFIER_RE.fullmatch(part) for part in parts):
                raise DatabaseAuditError(f"Identifier {name} tidak valid; hanya nama tabel/kolom, bukan SQL.")
        if self.event_id_column and not IDENTIFIER_RE.fullmatch(str(self.event_id_column)):
            raise DatabaseAuditError("Kolom ID event tidak valid.")
        if engine == "sqlserver" and not IDENTIFIER_RE.fullmatch(str(self.schema or "dbo")):
            raise DatabaseAuditError("Schema SQL Server tidak valid.")
        if engine in {"mysql", "mariadb"}:
            ca = Path(str(self.tls_ca_file or "")).expanduser()
            if not str(self.tls_ca_file or "") or not ca.is_file():
                raise DatabaseAuditError("Koneksi MySQL/MariaDB wajib memakai file CA TLS yang tersedia.")
        return DatabaseAuditConfig(
            engine=engine, host=host, database=str(self.database).strip(), username=str(self.username).strip(),
            source_table=str(self.source_table), timestamp_column=str(self.timestamp_column),
            event_type_column=str(self.event_type_column), host_column=str(self.host_column),
            source_column=str(self.source_column), actor_column=str(self.actor_column),
            message_column=str(self.message_column), event_id_column=str(self.event_id_column or ""),
            schema=str(self.schema or "dbo"), port=port, tls_ca_file=str(self.tls_ca_file or ""),
            timeout_seconds=timeout,
        )


def _quote_identifier(value: str, engine: str) -> str:
    parts = value.split(".")
    if any(not IDENTIFIER_RE.fullmatch(p) for p in parts):
        raise DatabaseAuditError("Identifier SQL tidak valid.")
    if engine == "sqlserver":
        return ".".join(f"[{p}]" for p in parts)
    return ".".join(f"`{p}`" for p in parts)


def _as_utc_string(value: Any) -> str:
    if isinstance(value, datetime):
        parsed = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    raw = str(value or "").strip()
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError as exc:
        raise DatabaseAuditError("Timestamp dari sumber audit bukan datetime/ISO-8601 valid.") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _event(raw: Mapping[str, Any], config: DatabaseAuditConfig) -> dict[str, Any]:
    timestamp = _as_utc_string(raw.get("timestamp_utc"))
    source_name = str(raw.get("source") or f"{config.engine}-audit")[:64]
    host_id = str(raw.get("host_id") or config.host)[:128]
    event_type_raw = str(raw.get("event_type") or "custom security event")
    event_type_key = event_type_raw.strip().upper().replace("-", "_").replace(" ", "_")
    aliases = {
        "LOGIN_FAILED": "AUTH_FAILURE", "FAILED_LOGIN": "AUTH_FAILURE", "AUTHENTICATION_FAILURE": "AUTH_FAILURE",
        "LOGIN_SUCCESS": "AUTH_SUCCESS", "PRIVILEGE_ESCALATION": "PRIVILEGE_USE", "SUDO": "PRIVILEGE_USE",
        "FILE_MODIFIED": "FILE_CHANGE", "CONFIG_CHANGE": "SERVICE_CHANGE",
    }
    allowed = {"AUTH_FAILURE", "AUTH_SUCCESS", "PRIVILEGE_USE", "FILE_CHANGE", "SERVICE_CHANGE", "WEB_AUTH_FAILURE", "WEB_AUTH_SUCCESS", "API_AUTH_FAILURE", "API_AUTH_SUCCESS", "AGENT_HEALTH", "CUSTOM_SECURITY_EVENT", "MALWARE_DETECTED"}
    event_type = aliases.get(event_type_key, event_type_key)
    if event_type not in allowed:
        event_type = "CUSTOM_SECURITY_EVENT"
    source_ip = ""
    message = str(raw.get("message") or "")[:256]
    found_ip = re.search(r"(?<![\w.])(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f:]{3,})(?![\w.])", message)
    if found_ip:
        try:
            source_ip = str(ipaddress.ip_address(found_ip.group(0).strip("[]")))
        except ValueError:
            pass
    event_id_raw = str(raw.get("event_id") or "")
    if not re.fullmatch(r"[A-Fa-f0-9]{16,128}", event_id_raw):
        event_id_raw = hashlib.sha256((config.engine + "\x00" + timestamp + "\x00" + host_id + "\x00" + source_name + "\x00" + message).encode("utf-8", errors="replace")).hexdigest()
    canonical = {
        "event_id": event_id_raw.lower(), "timestamp_utc": timestamp, "event_type": event_type,
        "host_id": host_id, "source": source_name, "actor": str(raw.get("actor") or "unknown")[:128],
        "source_ip": source_ip,
        "details": {"message_excerpt": message, "service": source_name, "reason": "database_audit_source"},
    }
    return normalize_server_event(canonical)


class DatabaseAuditConnector:
    """Poll a configured audit view/table using one fixed parameterized SELECT query."""

    def __init__(self, config: DatabaseAuditConfig, *, password: str, driver_module: Any = None):
        self.config = config.validated()
        self._password = str(password or "")
        if not self._password:
            raise DatabaseAuditError("Password harus diberikan dari Secure Storage OS.")
        self._driver_module = driver_module

    def _driver(self) -> Any:
        if self._driver_module is not None:
            return self._driver_module
        package = "pyodbc" if self.config.engine == "sqlserver" else "pymysql"
        try:
            return importlib.import_module(package)
        except ImportError as exc:
            raise DatabaseAuditError(f"Driver {package} belum terpasang; pasang extra konektor database yang sesuai.") from exc

    def _connect(self, driver: Any) -> Any:
        c = self.config
        if c.engine in {"mysql", "mariadb"}:
            ssl_options = {"ca": str(Path(c.tls_ca_file).expanduser()), "check_hostname": True}
            kwargs = {
                "host": c.host, "port": c.port, "user": c.username, "password": self._password,
                "database": c.database, "connect_timeout": c.timeout_seconds,
                "read_timeout": c.timeout_seconds, "write_timeout": c.timeout_seconds,
                "charset": "utf8mb4", "autocommit": False, "ssl": ssl_options,
            }
            dict_cursor = getattr(getattr(driver, "cursors", None), "DictCursor", None)
            if dict_cursor is not None:
                kwargs["cursorclass"] = dict_cursor
            return driver.connect(**kwargs)
        # SQL Server uses the OS trust store and rejects untrusted certificates.
        def odbc(value: str) -> str:
            return "{" + value.replace("}", "}}") + "}"
        server = f"tcp:{c.host},{c.port}"
        connection_string = (
            f"DRIVER={odbc('ODBC Driver 18 for SQL Server')};SERVER={odbc(server)};"
            f"DATABASE={odbc(c.database)};UID={odbc(c.username)};PWD={odbc(self._password)};"
            "Encrypt=yes;TrustServerCertificate=no;ApplicationIntent=ReadOnly;"
            f"Connection Timeout={c.timeout_seconds};"
        )
        return driver.connect(connection_string, timeout=c.timeout_seconds)

    def _query(self, cursor: Any, since: Any, limit: int) -> None:
        c = self.config
        source_table = _quote_identifier(c.source_table, c.engine)
        columns = [
            f"{_quote_identifier(c.timestamp_column, c.engine)} AS timestamp_utc",
            f"{_quote_identifier(c.event_type_column, c.engine)} AS event_type",
            f"{_quote_identifier(c.host_column, c.engine)} AS host_id",
            f"{_quote_identifier(c.source_column, c.engine)} AS source",
            f"{_quote_identifier(c.actor_column, c.engine)} AS actor",
            f"{_quote_identifier(c.message_column, c.engine)} AS message",
        ]
        if c.event_id_column:
            columns.insert(0, f"{_quote_identifier(c.event_id_column, c.engine)} AS event_id")
        else:
            columns.insert(0, "NULL AS event_id")
        timestamp_column = _quote_identifier(c.timestamp_column, c.engine)
        if c.engine == "sqlserver":
            schema = _quote_identifier(c.schema, "sqlserver")
            table = f"{schema}.{source_table}" if "." not in c.source_table else source_table
            query = f"SELECT TOP (?) {', '.join(columns)} FROM {table} WHERE {timestamp_column} > ? ORDER BY {timestamp_column} ASC"
            cursor.execute(query, (limit, since))
        else:
            query = f"SELECT {', '.join(columns)} FROM {source_table} WHERE {timestamp_column} > %s ORDER BY {timestamp_column} ASC LIMIT %s"
            cursor.execute(query, (since, limit))

    @staticmethod
    def _rows(cursor: Any) -> list[dict[str, Any]]:
        rows = cursor.fetchall()
        if not rows:
            return []
        if isinstance(rows[0], Mapping):
            return [dict(row) for row in rows]
        names = [str(desc[0]) for desc in (cursor.description or [])]
        return [dict(zip(names, row)) for row in rows]

    def fetch_events(self, *, since: datetime | None = None, limit: int = 100) -> list[dict[str, Any]]:
        try:
            bound_limit = int(limit)
        except (TypeError, ValueError) as exc:
            raise DatabaseAuditError("Limit event database harus bilangan bulat 1–500.") from exc
        if not 1 <= bound_limit <= MAX_LIMIT:
            raise DatabaseAuditError("Limit event database harus 1–500.")
        if since is None:
            since = datetime.now(timezone.utc) - timedelta(hours=24)
        if not isinstance(since, datetime):
            raise DatabaseAuditError("Watermark/since harus datetime yang valid.")
        if since.tzinfo is None:
            raise DatabaseAuditError("Watermark/since harus memiliki zona waktu.")
        since_value = since.astimezone(timezone.utc).replace(tzinfo=None) if self.config.engine != "sqlserver" else since.astimezone(timezone.utc).replace(tzinfo=None)
        conn = None
        try:
            conn = self._connect(self._driver())
            cursor = conn.cursor()
            if self.config.engine in {"mysql", "mariadb"}:
                # Enforce read-only transaction semantics in addition to requiring a
                # dedicated DB account with SELECT-only grants.
                cursor.execute("SET SESSION TRANSACTION READ ONLY")
            self._query(cursor, since_value, bound_limit)
            raw_rows = self._rows(cursor)
            if len(raw_rows) > bound_limit:
                raise DatabaseAuditError("Sumber audit mengembalikan lebih banyak baris daripada limit.")
            return [_event(row, self.config) for row in raw_rows]
        except DatabaseAuditError:
            raise
        except Exception as exc:
            raise DatabaseAuditError(f"Query sumber audit gagal ({type(exc).__name__}); secret dan SQL result tidak ditampilkan.") from exc
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass

    def close(self) -> None:
        """Connections are closed after each fetch; no credentials are retained externally."""
        return None
