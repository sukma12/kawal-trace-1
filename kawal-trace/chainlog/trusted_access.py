"""Trusted Access & Response — Build 14 (Kawal Trace v10 target).

This module implements the data model and local helpers for:

* Trusted Members (official members with roles)
* Trusted Devices (device identity + crypto key material binding)
* Access Verification (prove possession of device key on each connection)
* Unauthorized Access recording
* Incident History and response audit trail

It is designed to integrate with the existing optional-server-api membership
table and the local UserRegistry / device_identity without rewriting them.

Design principles (matching the product rules):
- Official membership is not just an email or username; it requires a verified
  device identity and a cryptographic key that the member proves possession of.
- Even official members are monitored; compromised accounts or devices can still
  be treated as incidents.
- Administrator accounts are protected from automatic force-disconnect mistakes.
- All response actions are audited with IP, account, time, session, reason and outcome.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .core import utc_now

# --------------------------------------------------------------------------- constants
MEMBER_ID_RE_LEN = (8, 128)
INVITE_CODE_BYTES = 24
DEVICE_KEY_BYTES = 32
INCIDENT_RETENTION_DAYS = 90


class TrustedAccessError(ValueError):
    """Invalid trusted-access operation or data."""


@dataclass
class TrustedMember:
    member_id: str
    display_name: str
    email: str
    role: str  # admin | operator | viewer | member
    status: str  # PENDING | ACTIVE | REVOKED
    created_at_utc: str
    activated_at_utc: str = ""
    revoked_at_utc: str = ""
    notes: str = ""

    def public_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TrustedDevice:
    device_id: str
    member_id: str
    platform: str  # Windows | Android | Linux | unknown
    public_key_pem: str  # device public key (Ed25519 or similar)
    fingerprint: str  # stable hash of public key
    status: str  # PENDING | TRUSTED | REVOKED
    enrolled_at_utc: str
    last_seen_at_utc: str = ""
    label: str = ""

    def public_dict(self) -> dict[str, Any]:
        d = asdict(self)
        # never expose private material; public key is fine
        return d


@dataclass
class Invitation:
    invite_code: str
    member_id: str
    email: str
    display_name: str
    role: str
    created_at_utc: str
    expires_at_utc: str
    used_at_utc: str = ""
    status: str = "OPEN"  # OPEN | USED | EXPIRED | REVOKED

    def public_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class IncidentRecord:
    incident_id: str
    detected_at_utc: str
    source_ip: str
    account: str
    device_id: str
    session_id: str
    classification: str  # OFFICIAL | UNKNOWN | SUSPICIOUS | INTRUDER
    reason: str
    actions_taken: list[str] = field(default_factory=list)
    outcome: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)

    def public_dict(self) -> dict[str, Any]:
        return asdict(self)


class TrustedAccessStore:
    """Local SQLite store for invitations, members, devices and incident history.

    This is the client/dashboard side companion to the server-side member_accounts
    table. It does not replace server authority; it records the local view and
    invitation workflow so the admin can issue activation invites.
    """

    FORMAT = "Kawal-Trace-trusted-access"
    VERSION = 1

    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path).expanduser().resolve()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _initialize(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS trusted_members (
                    member_id TEXT PRIMARY KEY,
                    display_name TEXT NOT NULL,
                    email TEXT NOT NULL DEFAULT '',
                    role TEXT NOT NULL DEFAULT 'member',
                    status TEXT NOT NULL DEFAULT 'PENDING',
                    created_at_utc TEXT NOT NULL,
                    activated_at_utc TEXT NOT NULL DEFAULT '',
                    revoked_at_utc TEXT NOT NULL DEFAULT '',
                    notes TEXT NOT NULL DEFAULT ''
                );
                CREATE TABLE IF NOT EXISTS trusted_devices (
                    device_id TEXT PRIMARY KEY,
                    member_id TEXT NOT NULL,
                    platform TEXT NOT NULL DEFAULT 'unknown',
                    public_key_pem TEXT NOT NULL DEFAULT '',
                    fingerprint TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'PENDING',
                    enrolled_at_utc TEXT NOT NULL,
                    last_seen_at_utc TEXT NOT NULL DEFAULT '',
                    label TEXT NOT NULL DEFAULT '',
                    FOREIGN KEY (member_id) REFERENCES trusted_members(member_id)
                );
                CREATE TABLE IF NOT EXISTS invitations (
                    invite_code TEXT PRIMARY KEY,
                    member_id TEXT NOT NULL,
                    email TEXT NOT NULL,
                    display_name TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'member',
                    created_at_utc TEXT NOT NULL,
                    expires_at_utc TEXT NOT NULL,
                    used_at_utc TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'OPEN',
                    FOREIGN KEY (member_id) REFERENCES trusted_members(member_id)
                );
                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY,
                    detected_at_utc TEXT NOT NULL,
                    source_ip TEXT NOT NULL DEFAULT '',
                    account TEXT NOT NULL DEFAULT '',
                    device_id TEXT NOT NULL DEFAULT '',
                    session_id TEXT NOT NULL DEFAULT '',
                    classification TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    actions_taken_json TEXT NOT NULL DEFAULT '[]',
                    outcome TEXT NOT NULL DEFAULT '',
                    evidence_json TEXT NOT NULL DEFAULT '{}'
                );
                CREATE INDEX IF NOT EXISTS idx_incidents_detected
                    ON incidents(detected_at_utc DESC);
                CREATE INDEX IF NOT EXISTS idx_devices_member
                    ON trusted_devices(member_id);
                CREATE INDEX IF NOT EXISTS idx_invites_status
                    ON invitations(status, expires_at_utc);
                """
            )
            conn.commit()

    # ------------------------------------------------------------------ members
    def create_member(
        self,
        display_name: str,
        email: str = "",
        role: str = "member",
        notes: str = "",
    ) -> TrustedMember:
        display_name = (display_name or "").strip()
        if not display_name or len(display_name) > 100:
            raise TrustedAccessError("Nama anggota wajib 1–100 karakter.")
        email = (email or "").strip().lower()
        role = (role or "member").strip().lower()
        if role not in {"admin", "operator", "viewer", "member"}:
            raise TrustedAccessError("Peran tidak valid.")
        member_id = "m_" + secrets.token_hex(12)
        now = utc_now()
        member = TrustedMember(
            member_id=member_id,
            display_name=display_name,
            email=email,
            role=role,
            status="PENDING",
            created_at_utc=now,
            notes=notes or "",
        )
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO trusted_members
                (member_id, display_name, email, role, status, created_at_utc, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (member.member_id, member.display_name, member.email, member.role,
                 member.status, member.created_at_utc, member.notes),
            )
            conn.commit()
        return member

    def list_members(self, status: str | None = None) -> list[TrustedMember]:
        with self._connect() as conn:
            if status:
                rows = conn.execute(
                    "SELECT * FROM trusted_members WHERE status=? ORDER BY created_at_utc DESC",
                    (status,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM trusted_members ORDER BY created_at_utc DESC"
                ).fetchall()
        return [self._row_to_member(r) for r in rows]

    def get_member(self, member_id: str) -> TrustedMember | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM trusted_members WHERE member_id=?", (member_id,)
            ).fetchone()
        return self._row_to_member(row) if row else None

    def revoke_member(self, member_id: str) -> TrustedMember:
        now = utc_now()
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE trusted_members
                SET status='REVOKED', revoked_at_utc=?
                WHERE member_id=?
                """,
                (now, member_id),
            )
            conn.execute(
                """
                UPDATE trusted_devices SET status='REVOKED'
                WHERE member_id=? AND status != 'REVOKED'
                """,
                (member_id,),
            )
            conn.commit()
        member = self.get_member(member_id)
        if not member:
            raise TrustedAccessError("Anggota tidak ditemukan.")
        return member

    def activate_member(self, member_id: str) -> TrustedMember:
        now = utc_now()
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE trusted_members
                SET status='ACTIVE', activated_at_utc=?
                WHERE member_id=? AND status != 'REVOKED'
                """,
                (now, member_id),
            )
            conn.commit()
        member = self.get_member(member_id)
        if not member:
            raise TrustedAccessError("Anggota tidak ditemukan.")
        return member

    def _row_to_member(self, row: sqlite3.Row) -> TrustedMember:
        return TrustedMember(
            member_id=row["member_id"],
            display_name=row["display_name"],
            email=row["email"],
            role=row["role"],
            status=row["status"],
            created_at_utc=row["created_at_utc"],
            activated_at_utc=row["activated_at_utc"] or "",
            revoked_at_utc=row["revoked_at_utc"] or "",
            notes=row["notes"] or "",
        )

    # ------------------------------------------------------------------ invitations (admin creates, member activates)
    def create_invitation(
        self,
        display_name: str,
        email: str,
        role: str = "member",
        ttl_hours: int = 72,
    ) -> tuple[TrustedMember, Invitation]:
        """Admin flow step 1–2: create member + invitation activation code."""
        member = self.create_member(display_name=display_name, email=email, role=role)
        invite_code = secrets.token_urlsafe(INVITE_CODE_BYTES)
        now = time.time()
        created = utc_now()
        expires = time.strftime(
            "%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(now + max(1, ttl_hours) * 3600)
        )
        inv = Invitation(
            invite_code=invite_code,
            member_id=member.member_id,
            email=email.strip().lower(),
            display_name=display_name.strip(),
            role=role,
            created_at_utc=created,
            expires_at_utc=expires,
            status="OPEN",
        )
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO invitations
                (invite_code, member_id, email, display_name, role,
                 created_at_utc, expires_at_utc, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    inv.invite_code, inv.member_id, inv.email, inv.display_name,
                    inv.role, inv.created_at_utc, inv.expires_at_utc, inv.status,
                ),
            )
            conn.commit()
        return member, inv

    def get_invitation(self, invite_code: str) -> Invitation | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM invitations WHERE invite_code=?", (invite_code,)
            ).fetchone()
        if not row:
            return None
        return Invitation(
            invite_code=row["invite_code"],
            member_id=row["member_id"],
            email=row["email"],
            display_name=row["display_name"],
            role=row["role"],
            created_at_utc=row["created_at_utc"],
            expires_at_utc=row["expires_at_utc"],
            used_at_utc=row["used_at_utc"] or "",
            status=row["status"],
        )

    def consume_invitation(
        self,
        invite_code: str,
        device_id: str,
        platform: str,
        public_key_pem: str,
        label: str = "",
    ) -> tuple[TrustedMember, TrustedDevice]:
        """Member flow steps 4–6: verify invite, register device identity + key."""
        inv = self.get_invitation(invite_code)
        if not inv:
            raise TrustedAccessError("Kode undangan tidak ditemukan.")
        if inv.status != "OPEN":
            raise TrustedAccessError(f"Undangan sudah {inv.status}.")
        # simple expiry check (lexicographic ISO works for Z timestamps)
        if inv.expires_at_utc < utc_now():
            with self._connect() as conn:
                conn.execute(
                    "UPDATE invitations SET status='EXPIRED' WHERE invite_code=?",
                    (invite_code,),
                )
                conn.commit()
            raise TrustedAccessError("Undangan sudah kedaluwarsa.")
        if not device_id or len(device_id) < 8:
            raise TrustedAccessError("Device ID tidak valid.")
        fingerprint = hashlib.sha256(public_key_pem.encode("utf-8")).hexdigest() if public_key_pem else ""
        now = utc_now()
        device = TrustedDevice(
            device_id=device_id,
            member_id=inv.member_id,
            platform=platform or "unknown",
            public_key_pem=public_key_pem or "",
            fingerprint=fingerprint,
            status="TRUSTED",
            enrolled_at_utc=now,
            last_seen_at_utc=now,
            label=label or "",
        )
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE invitations
                SET status='USED', used_at_utc=?
                WHERE invite_code=?
                """,
                (now, invite_code),
            )
            conn.execute(
                """
                UPDATE trusted_members
                SET status='ACTIVE', activated_at_utc=?
                WHERE member_id=?
                """,
                (now, inv.member_id),
            )
            conn.execute(
                """
                INSERT OR REPLACE INTO trusted_devices
                (device_id, member_id, platform, public_key_pem, fingerprint,
                 status, enrolled_at_utc, last_seen_at_utc, label)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    device.device_id, device.member_id, device.platform,
                    device.public_key_pem, device.fingerprint, device.status,
                    device.enrolled_at_utc, device.last_seen_at_utc, device.label,
                ),
            )
            conn.commit()
        member = self.get_member(inv.member_id)
        assert member is not None
        return member, device

    # ------------------------------------------------------------------ devices
    def list_devices(self, member_id: str | None = None) -> list[TrustedDevice]:
        with self._connect() as conn:
            if member_id:
                rows = conn.execute(
                    "SELECT * FROM trusted_devices WHERE member_id=? ORDER BY enrolled_at_utc DESC",
                    (member_id,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM trusted_devices ORDER BY enrolled_at_utc DESC"
                ).fetchall()
        return [self._row_to_device(r) for r in rows]

    def revoke_device(self, device_id: str) -> TrustedDevice:
        with self._connect() as conn:
            conn.execute(
                "UPDATE trusted_devices SET status='REVOKED' WHERE device_id=?",
                (device_id,),
            )
            conn.commit()
            row = conn.execute(
                "SELECT * FROM trusted_devices WHERE device_id=?", (device_id,)
            ).fetchone()
        if not row:
            raise TrustedAccessError("Perangkat tidak ditemukan.")
        return self._row_to_device(row)

    def _row_to_device(self, row: sqlite3.Row) -> TrustedDevice:
        return TrustedDevice(
            device_id=row["device_id"],
            member_id=row["member_id"],
            platform=row["platform"],
            public_key_pem=row["public_key_pem"],
            fingerprint=row["fingerprint"],
            status=row["status"],
            enrolled_at_utc=row["enrolled_at_utc"],
            last_seen_at_utc=row["last_seen_at_utc"] or "",
            label=row["label"] or "",
        )

    # ------------------------------------------------------------------ access verification helper
    def verify_device_key(
        self,
        device_id: str,
        challenge: bytes,
        signature: bytes,
    ) -> bool:
        """Prove possession of the device private key (client-side verification helper).

        The actual private key never leaves the device. Server/API side should
        perform the same check with the stored public key.
        """
        device = None
        for d in self.list_devices():
            if d.device_id == device_id and d.status == "TRUSTED":
                device = d
                break
        if not device or not device.public_key_pem:
            return False
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            from cryptography.hazmat.primitives.serialization import load_pem_public_key

            pub = load_pem_public_key(device.public_key_pem.encode("utf-8"))
            if not isinstance(pub, Ed25519PublicKey):
                return False
            pub.verify(signature, challenge)
            return True
        except Exception:
            return False

    # ------------------------------------------------------------------ incidents
    def record_incident(
        self,
        source_ip: str,
        account: str,
        device_id: str,
        session_id: str,
        classification: str,
        reason: str,
        actions_taken: list[str] | None = None,
        outcome: str = "",
        evidence: dict[str, Any] | None = None,
    ) -> IncidentRecord:
        incident_id = "inc_" + secrets.token_hex(10)
        rec = IncidentRecord(
            incident_id=incident_id,
            detected_at_utc=utc_now(),
            source_ip=source_ip or "",
            account=account or "",
            device_id=device_id or "",
            session_id=session_id or "",
            classification=classification,
            reason=reason,
            actions_taken=list(actions_taken or []),
            outcome=outcome or "",
            evidence=dict(evidence or {}),
        )
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO incidents
                (incident_id, detected_at_utc, source_ip, account, device_id,
                 session_id, classification, reason, actions_taken_json,
                 outcome, evidence_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    rec.incident_id, rec.detected_at_utc, rec.source_ip, rec.account,
                    rec.device_id, rec.session_id, rec.classification, rec.reason,
                    json.dumps(rec.actions_taken), rec.outcome, json.dumps(rec.evidence),
                ),
            )
            conn.commit()
        return rec

    def list_incidents(self, limit: int = 100) -> list[IncidentRecord]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM incidents ORDER BY detected_at_utc DESC LIMIT ?",
                (max(1, min(limit, 1000)),),
            ).fetchall()
        result: list[IncidentRecord] = []
        for r in rows:
            result.append(
                IncidentRecord(
                    incident_id=r["incident_id"],
                    detected_at_utc=r["detected_at_utc"],
                    source_ip=r["source_ip"],
                    account=r["account"],
                    device_id=r["device_id"],
                    session_id=r["session_id"],
                    classification=r["classification"],
                    reason=r["reason"],
                    actions_taken=json.loads(r["actions_taken_json"] or "[]"),
                    outcome=r["outcome"] or "",
                    evidence=json.loads(r["evidence_json"] or "{}"),
                )
            )
        return result

    def summarize(self) -> dict[str, int]:
        with self._connect() as conn:
            members = conn.execute(
                "SELECT status, COUNT(*) AS c FROM trusted_members GROUP BY status"
            ).fetchall()
            devices = conn.execute(
                "SELECT status, COUNT(*) AS c FROM trusted_devices GROUP BY status"
            ).fetchall()
            incidents = conn.execute("SELECT COUNT(*) AS c FROM incidents").fetchone()
        return {
            "members": {r["status"]: r["c"] for r in members},
            "devices": {r["status"]: r["c"] for r in devices},
            "incidents_total": int(incidents["c"]) if incidents else 0,
        }


def generate_device_keypair() -> tuple[str, str]:
    """Generate an Ed25519 key pair for a new trusted device.

    Returns (private_pem, public_pem). Private key must stay on the device only.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
    )

    private = Ed25519PrivateKey.generate()
    priv_pem = private.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
    ).decode("utf-8")
    pub_pem = private.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")
    return priv_pem, pub_pem


def sign_challenge(private_pem: str, challenge: bytes) -> bytes:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    key = load_pem_private_key(private_pem.encode("utf-8"), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise TrustedAccessError("Kunci privat bukan Ed25519.")
    return key.sign(challenge)
