"""Local authentication registry for the Kawal Trace application.

This protects application screens and operator attribution, not the Windows
account or the filesystem itself. A local administrator can still alter files.
"""
from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import sqlite3
import time
from pathlib import Path
from typing import Any

from .core import utc_now

PBKDF2_ITERATIONS = 600_000
MAX_FAILED_AUTH_ATTEMPTS = 5
AUTH_FAILURE_WINDOW_SECONDS = 300
AUTH_LOCKOUT_SECONDS = 60
AUTH_LOCKOUT_MAX_SECONDS = 3600          # repeated lockouts double the wait, up to one hour
AUTH_STRIKE_FORGET_SECONDS = 24 * 3600   # a quiet day forgets earlier lockouts
SESSION_DAYS = 30                        # sliding "remembered device" lifetime
SESSION_MAX_DAYS = 90                    # absolute cap: after this a password login is required again
MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 128
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{4,10}$")
EXISTING_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
VALID_ROLES = {"admin", "operator", "viewer"}
_DUMMY_SALT = b"KawalTrace-device-unlock-dummy-salt"


class AuthenticationError(Exception):
    """Raised when local account input is invalid or an account operation fails."""


def _derive(password: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=32)


class UserRegistry:
    """SQLite-backed local accounts using salted PBKDF2 password hashes."""

    def __init__(self, db_path: str | Path, device_fp: str | None = None):
        self.db_path = Path(db_path).expanduser().resolve()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._device_fp: str | None = None
        self._initialize()
        if device_fp:
            self.bind_device(device_fp)

    # ------------------------------------------------------------------ device binding
    @property
    def device_bound(self) -> bool:
        return self._device_fp is not None

    @property
    def device_id(self) -> str | None:
        """Stable pseudonymous identifier for this installation, never a raw hardware ID."""
        return self._device_fp

    def bind_device(self, device_fp: str) -> None:
        """Scope every account operation to this device's fingerprint.

        Accounts created before device binding existed (device_fp NULL) are adopted by the first
        device that binds; accounts bound to a different fingerprint stay in the file untouched but
        are invisible and unusable here, so this device is asked to create its own account.
        """
        fp = str(device_fp or "").strip()
        if not re.fullmatch(r"[0-9a-f]{64}", fp):
            raise AuthenticationError("ID perangkat tidak valid.")
        self._device_fp = fp
        with self._connect() as conn:
            conn.execute("UPDATE users SET device_fp=? WHERE device_fp IS NULL", (fp,))

    def _scope(self, alias: str = "") -> tuple[str, tuple[Any, ...]]:
        """SQL fragment limiting `users` rows to this device (empty when binding is not enabled)."""
        if self._device_fp is None:
            return "", ()
        prefix = f"{alias}." if alias else ""
        return f" AND {prefix}device_fp = ?", (self._device_fp,)

    def has_foreign_accounts(self) -> bool:
        """True when this file holds accounts that belong to some OTHER device."""
        if self._device_fp is None:
            return False
        with self._connect() as conn:
            return conn.execute("SELECT 1 FROM users WHERE device_fp IS NOT NULL AND device_fp<>? LIMIT 1",
                                (self._device_fp,)).fetchone() is not None

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("PRAGMA synchronous=FULL")
        return conn

    def _initialize(self) -> None:
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    salt BLOB NOT NULL,
                    password_hash BLOB NOT NULL,
                    iterations INTEGER NOT NULL DEFAULT 600000,
                    role TEXT NOT NULL CHECK(role IN ('admin','operator','viewer')),
                    active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
                    created_at_utc TEXT NOT NULL
                )
            """)
            # Preserve accounts made by early 1.2 test builds before iteration count
            # became a stored per-user value (those hashes used 310,000 iterations).
            columns = {str(row["name"]) for row in conn.execute("PRAGMA table_info(users)").fetchall()}
            if "iterations" not in columns:
                conn.execute("ALTER TABLE users ADD COLUMN iterations INTEGER NOT NULL DEFAULT 310000")
            if "device_fp" not in columns:
                conn.execute("ALTER TABLE users ADD COLUMN device_fp TEXT")
            # Persistent throttle slows repeated password guessing across app restarts.
            # This is an application-level guardrail, not a replacement for OS account security.
            conn.execute("""
                CREATE TABLE IF NOT EXISTS auth_attempts (
                    username_key TEXT PRIMARY KEY,
                    failures INTEGER NOT NULL,
                    window_started REAL NOT NULL,
                    locked_until REAL NOT NULL DEFAULT 0
                )
            """)
            # Optional device-local PIN unlock. The main account password remains the
            # recovery path; the PIN never leaves this installation and is PBKDF2-hashed.
            conn.execute("""
                CREATE TABLE IF NOT EXISTS device_unlock (
                    username TEXT PRIMARY KEY COLLATE NOCASE,
                    salt BLOB NOT NULL,
                    pin_hash BLOB NOT NULL,
                    iterations INTEGER NOT NULL DEFAULT 600000,
                    created_at_utc TEXT NOT NULL,
                    FOREIGN KEY(username) REFERENCES users(username) ON DELETE CASCADE
                )
            """)
            attempt_columns = {str(row["name"]) for row in conn.execute("PRAGMA table_info(auth_attempts)").fetchall()}
            if "strikes" not in attempt_columns:
                conn.execute("ALTER TABLE auth_attempts ADD COLUMN strikes INTEGER NOT NULL DEFAULT 0")
            if "last_failure" not in attempt_columns:
                conn.execute("ALTER TABLE auth_attempts ADD COLUMN last_failure REAL NOT NULL DEFAULT 0")
            # "Remembered device" sessions: only a SHA-256 of the random token is stored.
            conn.execute("""
                CREATE TABLE IF NOT EXISTS trusted_sessions (
                    token_hash TEXT PRIMARY KEY,
                    username TEXT NOT NULL COLLATE NOCASE,
                    device_fp TEXT NOT NULL,
                    origin_epoch REAL NOT NULL,
                    expires_epoch REAL NOT NULL,
                    last_used_epoch REAL NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS app_meta (
                    meta_key TEXT PRIMARY KEY,
                    meta_value TEXT NOT NULL,
                    updated_at_utc TEXT NOT NULL
                )
            """)

    def needs_legacy_credential_rotation(self) -> bool:
        """Detect old installs that have not recorded an explicit personal-account setup.

        Early releases may contain an account but no setup-version marker. Such an
        install is moved to a verified credential-rotation screen exactly once. This
        never creates/resets an account and never deletes identity or audit data.
        """
        with self._connect() as conn:
            bootstrap_marker = conn.execute(
                "SELECT 1 FROM app_meta WHERE meta_key='default_admin_bootstrap_v1'"
            ).fetchone()
            setup_marker = conn.execute(
                "SELECT 1 FROM app_meta WHERE meta_key='local_credentials_setup_v1'"
            ).fetchone()
            policy_marker = conn.execute(
                "SELECT 1 FROM app_meta WHERE meta_key='local_credentials_setup_v2'"
            ).fetchone()
            scope_sql, scope_args = self._scope()
            users_count = int(conn.execute("SELECT COUNT(*) FROM users WHERE 1=1" + scope_sql, scope_args).fetchone()[0])
        # v2 marks accounts that have explicitly adopted the enforced 4–10 username
        # and the password policy (now 8–128 characters; v2 accounts that used the older
        # 6–12 policy keep working because login never re-checks length). Upgrading v1 installs triggers a verified, one-time
        # credential rotation instead of silently leaving incompatible legacy fields.
        return users_count > 0 and (
            bootstrap_marker is not None or setup_marker is None or policy_marker is None
        )

    def change_admin_credentials(
        self,
        current_username: str,
        current_password: str,
        new_username: str,
        new_password: str,
    ) -> dict[str, Any]:
        """Change local administrator credentials only after verifying the old password.

        This operation does not erase accounts, audit logs, or connector settings. It
        updates the account row and any linked device PIN username in one transaction.
        """
        # Existing installations may have usernames outside the new 4–10 character
        # policy. Allow them to authenticate and rotate to the current policy without
        # locking themselves out. The replacement username is always validated strictly.
        current_username = self.validate_existing_username(current_username)
        new_username = self.validate_username(new_username)
        new_password = self.validate_password(new_password)
        authenticated = self.authenticate(current_username, current_password)
        if not authenticated or authenticated.get("role") != "admin":
            raise AuthenticationError("Username/kata sandi lama administrator tidak valid.")

        salt = secrets.token_bytes(16)
        password_hash = _derive(new_password, salt)
        old_key = current_username.casefold()
        new_key = new_username.casefold()
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute(
                "SELECT username, role, active FROM users WHERE username=? COLLATE NOCASE",
                (current_username,),
            ).fetchone()
            if existing is None or int(existing["active"]) != 1 or str(existing["role"]) != "admin":
                raise AuthenticationError("Akun administrator lama tidak ditemukan atau tidak aktif.")
            conflict = conn.execute(
                "SELECT 1 FROM users WHERE username=? COLLATE NOCASE AND username<>? COLLATE NOCASE",
                (new_username, current_username),
            ).fetchone()
            if conflict is not None:
                raise AuthenticationError("Username baru sudah digunakan akun lain.")

            stored_old_username = str(existing["username"])
            if old_key != new_key or stored_old_username != new_username:
                # SQLite foreign-key enforcement is intentionally not relied on here;
                # the PIN row is explicitly renamed in the same transaction.
                conn.execute(
                    "UPDATE device_unlock SET username=? WHERE username=? COLLATE NOCASE",
                    (new_username, stored_old_username),
                )
            conn.execute(
                "UPDATE users SET username=?, salt=?, password_hash=?, iterations=? "
                "WHERE username=? COLLATE NOCASE",
                (new_username, salt, password_hash, PBKDF2_ITERATIONS, stored_old_username),
            )
            conn.execute(
                "DELETE FROM auth_attempts WHERE username_key IN (?, ?, ?, ?)",
                (old_key, new_key, "device-pin:" + old_key, "device-pin:" + new_key),
            )
            conn.execute("DELETE FROM trusted_sessions WHERE username IN (?, ?) COLLATE NOCASE", (stored_old_username, new_username))
            now = utc_now()
            conn.execute(
                "DELETE FROM app_meta WHERE meta_key='default_admin_bootstrap_v1'"
            )
            for meta_key in ("local_credentials_setup_v1", "local_credentials_setup_v2"):
                conn.execute(
                    "INSERT INTO app_meta(meta_key,meta_value,updated_at_utc) VALUES(?,?,?) "
                    "ON CONFLICT(meta_key) DO UPDATE SET meta_value=excluded.meta_value, "
                    "updated_at_utc=excluded.updated_at_utc",
                    (meta_key, "complete", now),
                )
        return {"username": new_username, "role": "admin"}

    def rotate_legacy_credentials(
        self,
        current_username: str,
        current_password: str,
        new_username: str,
        new_password: str,
    ) -> dict[str, Any]:
        """Rotate a credential for an install marked as using the old bootstrap."""
        if not self.needs_legacy_credential_rotation():
            raise AuthenticationError("Migrasi kredensial lama tidak diperlukan.")
        return self.change_admin_credentials(
            current_username, current_password, new_username, new_password
        )

    def needs_setup(self) -> bool:
        scope_sql, scope_args = self._scope()
        with self._connect() as conn:
            return int(conn.execute("SELECT COUNT(*) FROM users WHERE 1=1" + scope_sql, scope_args).fetchone()[0]) == 0

    @staticmethod
    def validate_username(username: str) -> str:
        """Validate a newly-created username (4–10 ASCII characters)."""
        username = str(username).strip()
        if not USERNAME_RE.fullmatch(username):
            raise AuthenticationError(
                "Username harus 4–10 karakter: huruf, angka, titik, garis bawah, atau tanda hubung."
            )
        return username

    @staticmethod
    def validate_existing_username(username: str) -> str:
        """Allow legacy account names during login, PIN management, and migration."""
        username = str(username).strip()
        if not EXISTING_USERNAME_RE.fullmatch(username):
            raise AuthenticationError("Username akun lama tidak valid.")
        return username

    @staticmethod
    def validate_password(password: str) -> str:
        """Validate a new local password: 8–128 characters (passphrases are welcome)."""
        if not isinstance(password, str) or len(password) < MIN_PASSWORD_LENGTH:
            raise AuthenticationError(f"Kata sandi harus minimal {MIN_PASSWORD_LENGTH} karakter.")
        if len(password) > MAX_PASSWORD_LENGTH:
            raise AuthenticationError(f"Kata sandi maksimal {MAX_PASSWORD_LENGTH} karakter.")
        if password.lower() in {"123456", "12345678", "password", "password1", "admin123", "qwerty", "qwerty123", "11111111", "kawaltrace"}:
            raise AuthenticationError("Kata sandi terlalu umum. Pilih kombinasi yang lebih unik.")
        if len(set(password)) == 1:
            raise AuthenticationError("Kata sandi tidak boleh satu karakter yang diulang.")
        return password

    def create_initial_admin(self, username: str, password: str) -> dict[str, Any]:
        username = self.validate_username(username)
        password = self.validate_password(password)
        salt = secrets.token_bytes(16)
        with self._connect() as conn:
            # Serialize concurrent first-run attempts; only one admin may be created.
            conn.execute("BEGIN IMMEDIATE")
            scope_sql, scope_args = self._scope()
            if int(conn.execute("SELECT COUNT(*) FROM users WHERE 1=1" + scope_sql, scope_args).fetchone()[0]) != 0:
                raise AuthenticationError("Pengaturan awal sudah selesai. Silakan masuk menggunakan akun terdaftar.")
            try:
                conn.execute(
                    "INSERT INTO users(username,salt,password_hash,iterations,role,active,created_at_utc,device_fp) VALUES(?,?,?,?,?,1,?,?)",
                    (username, salt, _derive(password, salt), PBKDF2_ITERATIONS, "admin", utc_now(), self._device_fp),
                )
            except sqlite3.IntegrityError as exc:
                raise AuthenticationError("Username sudah dipakai. Pilih username lain untuk perangkat ini.") from exc
            now = utc_now()
            conn.execute(
                "DELETE FROM app_meta WHERE meta_key='default_admin_bootstrap_v1'"
            )
            for meta_key in ("local_credentials_setup_v1", "local_credentials_setup_v2"):
                conn.execute(
                    "INSERT INTO app_meta(meta_key,meta_value,updated_at_utc) VALUES(?,?,?) "
                    "ON CONFLICT(meta_key) DO UPDATE SET meta_value=excluded.meta_value, "
                    "updated_at_utc=excluded.updated_at_utc",
                    (meta_key, "complete", now),
                )
        return {"username": username, "role": "admin"}

    def add_user(self, username: str, password: str, role: str = "operator") -> dict[str, Any]:
        username = self.validate_username(username)
        password = self.validate_password(password)
        role = str(role).lower().strip()
        if role not in VALID_ROLES:
            raise AuthenticationError("Peran akun tidak dikenal.")
        salt = secrets.token_bytes(16)
        try:
            with self._connect() as conn:
                conn.execute(
                    "INSERT INTO users(username,salt,password_hash,iterations,role,active,created_at_utc,device_fp) VALUES(?,?,?,?,?,1,?,?)",
                    (username, salt, _derive(password, salt), PBKDF2_ITERATIONS, role, utc_now(), self._device_fp),
                )
        except sqlite3.IntegrityError as exc:
            raise AuthenticationError("Username sudah terdaftar.") from exc
        return {"username": username, "role": role}

    def authenticate(self, username: str, password: str) -> dict[str, Any] | None:
        username = str(username).strip()[:64]
        if not isinstance(password, str):
            password = ""
        username_key = username.casefold() or "<empty>"
        now = time.time()
        with self._connect() as conn:
            scope_sql, scope_args = self._scope()
            row = conn.execute(
                "SELECT username, salt, password_hash, iterations, role, active FROM users WHERE username=? COLLATE NOCASE" + scope_sql,
                (username, *scope_args),
            ).fetchone()
            throttle = conn.execute(
                "SELECT failures, window_started, locked_until FROM auth_attempts WHERE username_key=?",
                (username_key,),
            ).fetchone()

        # Do a dummy KDF while locked so a lockout does not reveal whether this is
        # a real account by returning much faster than an ordinary failed attempt.
        if throttle is not None and float(throttle["locked_until"]) > now:
            _derive(password[:256], _DUMMY_SALT)
            return None

        if row is None:
            # KDF for unknown usernames reduces simple timing-based account discovery.
            calculated = _derive(password[:256], _DUMMY_SALT)
            authenticated = False
        else:
            calculated = _derive(password[:256], bytes(row["salt"]), int(row["iterations"]))
            authenticated = int(row["active"]) == 1 and hmac.compare_digest(
                calculated, bytes(row["password_hash"])
            )

        if authenticated and row is not None:
            with self._connect() as conn:
                conn.execute("DELETE FROM auth_attempts WHERE username_key=?", (username_key,))
            return {"username": str(row["username"]), "role": str(row["role"])}

        self._record_failure(username_key, now)
        return None

    def _record_failure(self, key: str, now: float) -> None:
        """Count a failed guess. Five failures in a window lock the key; each repeat lockout doubles
        the wait (60s, 2m, 4m ... capped at 1h) and a quiet day forgets the earlier lockouts. State lives
        in SQLite so restarting the app does not reset it."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT failures, window_started, locked_until, strikes, last_failure FROM auth_attempts WHERE username_key=?",
                (key,),
            ).fetchone()
            strikes = int(row["strikes"]) if row is not None else 0
            if row is not None and now - float(row["last_failure"] or 0) > AUTH_STRIKE_FORGET_SECONDS:
                strikes = 0
            if (row is None or now - float(row["window_started"]) > AUTH_FAILURE_WINDOW_SECONDS
                    or float(row["locked_until"]) > 0):
                failures, window_started = 1, now
            else:
                failures, window_started = int(row["failures"]) + 1, float(row["window_started"])
            locked_until = 0.0
            if failures >= MAX_FAILED_AUTH_ATTEMPTS:
                locked_until = now + min(AUTH_LOCKOUT_MAX_SECONDS, AUTH_LOCKOUT_SECONDS * (2 ** min(strikes, 6)))
                strikes += 1
            conn.execute(
                "INSERT INTO auth_attempts(username_key,failures,window_started,locked_until,strikes,last_failure) VALUES(?,?,?,?,?,?) "
                "ON CONFLICT(username_key) DO UPDATE SET failures=excluded.failures, window_started=excluded.window_started, "
                "locked_until=excluded.locked_until, strikes=excluded.strikes, last_failure=excluded.last_failure",
                (key, failures, window_started, locked_until, strikes, now),
            )

    def list_users(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            scope_sql, scope_args = self._scope()
            rows = conn.execute(
                "SELECT username, role, active, created_at_utc FROM users WHERE 1=1" + scope_sql + " ORDER BY username COLLATE NOCASE",
                scope_args,
            ).fetchall()
        return [dict(row) for row in rows]

    @staticmethod
    def validate_device_pin(pin: str) -> str:
        pin = str(pin or "")
        if not re.fullmatch(r"[0-9]{8,12}", pin):
            raise AuthenticationError("PIN perangkat harus terdiri dari 8–12 angka.")
        if len(set(pin)) == 1:
            raise AuthenticationError("PIN terlalu mudah ditebak; jangan memakai angka yang sama berulang.")
        steps = [int(pin[i + 1]) - int(pin[i]) for i in range(len(pin) - 1)]
        if pin in {"00000000", "11111111", "11223344", "12121212", "10101010"} or (steps and (all(v == 1 for v in steps) or all(v == -1 for v in steps))):
            raise AuthenticationError("PIN terlalu umum atau berurutan. Pilih PIN yang unik.")
        return pin

    def set_device_pin(self, username: str, pin: str) -> None:
        """Enable PIN quick-unlock for an existing local account on this device."""
        username = self.validate_existing_username(username)
        pin = self.validate_device_pin(pin)
        salt = secrets.token_bytes(16)
        with self._connect() as conn:
            scope_sql, scope_args = self._scope()
            user = conn.execute(
                "SELECT username, active FROM users WHERE username=? COLLATE NOCASE" + scope_sql, (username, *scope_args)
            ).fetchone()
            if user is None or int(user["active"]) != 1:
                raise AuthenticationError("Akun lokal tidak ditemukan atau dinonaktifkan.")
            conn.execute(
                "INSERT INTO device_unlock(username,salt,pin_hash,iterations,created_at_utc) VALUES(?,?,?,?,?) "
                "ON CONFLICT(username) DO UPDATE SET salt=excluded.salt, pin_hash=excluded.pin_hash, "
                "iterations=excluded.iterations, created_at_utc=excluded.created_at_utc",
                (str(user["username"]), salt, _derive(pin, salt), PBKDF2_ITERATIONS, utc_now()),
            )

    def remove_device_pin(self, username: str) -> None:
        username = self.validate_existing_username(username)
        with self._connect() as conn:
            conn.execute("DELETE FROM device_unlock WHERE username=? COLLATE NOCASE", (username,))
            conn.execute("DELETE FROM auth_attempts WHERE username_key=?", ("device-pin:" + username.casefold(),))

    def has_device_pin(self, username: str) -> bool:
        username = str(username or "").strip()
        if not username:
            return False
        scope_sql, scope_args = self._scope("u")
        with self._connect() as conn:
            return conn.execute(
                "SELECT 1 FROM device_unlock d JOIN users u ON u.username=d.username "
                "WHERE d.username=? COLLATE NOCASE AND u.active=1" + scope_sql, (username, *scope_args)
            ).fetchone() is not None

    def device_unlock_user(self) -> dict[str, Any] | None:
        """Return the most recently enabled local account eligible for biometric unlock."""
        scope_sql, scope_args = self._scope("u")
        with self._connect() as conn:
            row = conn.execute(
                "SELECT u.username,u.role FROM users u JOIN device_unlock d ON u.username=d.username "
                "WHERE u.active=1" + scope_sql + " ORDER BY d.created_at_utc DESC LIMIT 1", scope_args
            ).fetchone()
        return dict(row) if row else None

    def list_device_pin_users(self) -> list[str]:
        scope_sql, scope_args = self._scope("u")
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT u.username FROM users u JOIN device_unlock d ON u.username=d.username "
                "WHERE u.active=1" + scope_sql + " ORDER BY d.created_at_utc DESC", scope_args
            ).fetchall()
        return [str(row["username"]) for row in rows]

    def authenticate_device_pin(self, username: str, pin: str) -> dict[str, Any] | None:
        """Authenticate with a local PIN and a persistent, per-account lockout."""
        username = str(username or "").strip()[:64]
        pin_input = str(pin or "")
        pin_too_long = len(pin_input) > 12
        pin = pin_input[:12]
        username_key = "device-pin:" + (username.casefold() or "<empty>")
        now = time.time()
        scope_sql, scope_args = self._scope("u")
        with self._connect() as conn:
            row = conn.execute(
                "SELECT u.username,u.role,u.active,d.salt,d.pin_hash,d.iterations "
                "FROM users u JOIN device_unlock d ON u.username=d.username "
                "WHERE u.username=? COLLATE NOCASE" + scope_sql, (username, *scope_args)
            ).fetchone()
            throttle = conn.execute(
                "SELECT failures,window_started,locked_until FROM auth_attempts WHERE username_key=?", (username_key,)
            ).fetchone()
        if throttle is not None and float(throttle["locked_until"]) > now:
            _derive(pin, _DUMMY_SALT)
            return None
        if row is None:
            _derive(pin, _DUMMY_SALT)
            ok = False
        else:
            calculated = _derive(pin, bytes(row["salt"]), int(row["iterations"]))
            ok = (not pin_too_long and int(row["active"]) == 1
                  and hmac.compare_digest(calculated, bytes(row["pin_hash"])))
        if ok and row is not None:
            with self._connect() as conn:
                conn.execute("DELETE FROM auth_attempts WHERE username_key=?", (username_key,))
            return {"username": str(row["username"]), "role": str(row["role"])}
        self._record_failure(username_key, now)
        return None

    # ------------------------------------------------------------------ remembered-device sessions
    @staticmethod
    def _token_hash(token: str) -> str:
        return hashlib.sha256(str(token).encode("utf-8")).hexdigest()

    def _insert_session(self, conn: sqlite3.Connection, username: str, origin: float, now: float) -> str:
        token = secrets.token_urlsafe(32)
        expires = min(now + SESSION_DAYS * 86400, origin + SESSION_MAX_DAYS * 86400)
        conn.execute(
            "INSERT INTO trusted_sessions(token_hash,username,device_fp,origin_epoch,expires_epoch,last_used_epoch) VALUES(?,?,?,?,?,?)",
            (self._token_hash(token), username, self._device_fp, origin, expires, now),
        )
        return token

    def create_trusted_session(self, username: str, *, now: float | None = None) -> str:
        """Remember THIS device for `username`. Returns the secret token to keep on the device."""
        if self._device_fp is None:
            raise AuthenticationError("Sesi perangkat membutuhkan ID perangkat.")
        now = time.time() if now is None else now
        username = str(username).strip()
        scope_sql, scope_args = self._scope()
        with self._connect() as conn:
            conn.execute("DELETE FROM trusted_sessions WHERE expires_epoch<?", (now,))
            user = conn.execute("SELECT username FROM users WHERE username=? COLLATE NOCASE AND active=1" + scope_sql,
                                (username, *scope_args)).fetchone()
            if user is None:
                raise AuthenticationError("Akun tidak ditemukan atau tidak aktif pada perangkat ini.")
            return self._insert_session(conn, str(user["username"]), now, now)

    def resume_trusted_session(self, token: str, *, now: float | None = None) -> tuple[dict[str, Any], str] | None:
        """Validate a remembered-device token. On success returns (user, rotated_token); the old token dies."""
        if self._device_fp is None or not isinstance(token, str) or not 32 <= len(token) <= 128:
            return None
        now = time.time() if now is None else now
        digest = self._token_hash(token)
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM trusted_sessions WHERE token_hash=?", (digest,)).fetchone()
            if row is None:
                return None
            conn.execute("DELETE FROM trusted_sessions WHERE token_hash=?", (digest,))  # one-time use: rotate or die
            if (not hmac.compare_digest(str(row["device_fp"]), self._device_fp) or float(row["expires_epoch"]) <= now
                    or now >= float(row["origin_epoch"]) + SESSION_MAX_DAYS * 86400):
                return None
            scope_sql, scope_args = self._scope()
            user = conn.execute("SELECT username, role FROM users WHERE username=? COLLATE NOCASE AND active=1" + scope_sql,
                                (str(row["username"]), *scope_args)).fetchone()
            if user is None:
                return None
            fresh = self._insert_session(conn, str(user["username"]), float(row["origin_epoch"]), now)
            return {"username": str(user["username"]), "role": str(user["role"])}, fresh

    def revoke_trusted_sessions(self, username: str | None = None) -> int:
        with self._connect() as conn:
            if username is None:
                if self._device_fp is None:
                    return conn.execute("DELETE FROM trusted_sessions").rowcount
                return conn.execute("DELETE FROM trusted_sessions WHERE device_fp=?", (self._device_fp,)).rowcount
            return conn.execute("DELETE FROM trusted_sessions WHERE username=? COLLATE NOCASE", (str(username).strip(),)).rowcount

    def count_trusted_sessions(self, username: str) -> int:
        with self._connect() as conn:
            return int(conn.execute("SELECT COUNT(*) FROM trusted_sessions WHERE username=? COLLATE NOCASE",
                                    (str(username).strip(),)).fetchone()[0])

    # ------------------------------------------------------------------ step-up verification
    def verify_step_up(self, username: str, secret: str) -> bool:
        """Re-check a signed-in user before a sensitive action. Shares the login lockout counters."""
        secret = str(secret or "")
        username = str(username or "").strip()
        if not username or not secret:
            return False
        if re.fullmatch(r"[0-9]{8,12}", secret) and self.has_device_pin(username):
            if self.authenticate_device_pin(username, secret):
                return True
        found = self.authenticate(username, secret)
        return bool(found) and str(found["username"]).casefold() == username.casefold()
