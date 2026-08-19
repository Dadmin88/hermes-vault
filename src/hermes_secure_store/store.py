from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import stat
import threading
import time
from collections.abc import Callable, Iterable
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .models import (
    AuditRecord,
    InjectionTarget,
    PrincipalContext,
    ReferenceInfo,
    RunContext,
    RunHandle,
    ScopeRef,
    VaultAccessDenied,
    VaultError,
    VaultUnavailable,
)

_MAX_BODY_BYTES = 1_048_576
_MAX_ENV_BYTES = 65_536
_MAX_REFERENCES = 64
_DEFAULT_MAX_USES = 256
_MAX_HANDLE_USES = 4096
_REFERENCE_PREFIX = "hvr1_"
_HANDLE_PREFIX = "hvh1_"


class VaultStore:
    """Encrypted local custody with scoped opaque references and run handles.

    The store deliberately separates control-plane operations from runtime
    redemption. Fleet may create/rotate/revoke references and mint handles, but
    only the runtime redemption path returns body bytes. References and handles
    are stored only as SHA-256 fingerprints in SQLite.
    """

    def __init__(
        self,
        root: Path,
        *,
        now_ms: Callable[[], int] | None = None,
    ) -> None:
        if not isinstance(root, Path) or not root.is_absolute():
            raise ValueError("store root must be an absolute Path")
        self._root = root
        self._now_ms = now_ms or (lambda: int(time.time() * 1000))
        if not callable(self._now_ms):
            raise ValueError("store clock is invalid")
        self._lock = threading.RLock()
        self._prepare_root()
        self._key = self._load_or_create_key()
        self._db_path = self._root / "state.db"
        self._initialize_database()

    @property
    def root(self) -> Path:
        return self._root

    def put(
        self,
        body: str | bytes,
        *,
        owner: PrincipalContext,
        scope: ScopeRef,
        injection: InjectionTarget,
        expires_at_ms: int | None = None,
    ) -> str:
        """Create a new logical item at version 1 and return an opaque reference."""
        self._validate_owner_scope(owner, scope)
        payload = self._validate_body(body, injection)
        expires_at_ms = self._validate_expiry(expires_at_ms)
        now = self._now()
        if expires_at_ms is not None and expires_at_ms <= now:
            raise ValueError("version expiry must be in the future")

        item_id = "item_" + secrets.token_urlsafe(18)
        reference = _REFERENCE_PREFIX + secrets.token_urlsafe(32)
        ref_fp = _fingerprint(reference)
        nonce = secrets.token_bytes(12)
        aad = _aad(item_id, 1, scope, injection)
        ciphertext = AESGCM(self._key).encrypt(nonce, payload, aad)

        with self._transaction() as conn:
            conn.execute(
                """INSERT INTO items(
                    item_id, owner_principal_id, owner_principal_kind,
                    scope_kind, scope_id, injection_kind, injection_target,
                    created_at_ms, revoked_at_ms
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)""",
                (
                    item_id,
                    owner.principal_id,
                    owner.principal_kind,
                    scope.kind,
                    scope.scope_id,
                    injection.kind,
                    injection.target,
                    now,
                ),
            )
            conn.execute(
                """INSERT INTO versions(
                    item_id, version, nonce, ciphertext, created_at_ms,
                    expires_at_ms, retired_at_ms, revoked_at_ms
                ) VALUES (?, 1, ?, ?, ?, ?, NULL, NULL)""",
                (item_id, nonce, ciphertext, now, expires_at_ms),
            )
            conn.execute(
                """INSERT INTO refs(reference_hash, item_id, created_at_ms, revoked_at_ms)
                   VALUES (?, ?, ?, NULL)""",
                (ref_fp, item_id, now),
            )
            self._audit(
                conn,
                action="put",
                outcome="success",
                principal=owner,
                scope=scope,
                reference_fingerprint=ref_fp,
                version=1,
                injection=injection,
            )
        return reference

    def rotate(
        self,
        reference: str,
        body: str | bytes,
        *,
        owner: PrincipalContext,
        expires_at_ms: int | None = None,
    ) -> int:
        """Create the next immutable version; new handles bind to it."""
        ref_fp = _reference_fingerprint(reference)
        expires_at_ms = self._validate_expiry(expires_at_ms)
        now = self._now()
        if expires_at_ms is not None and expires_at_ms <= now:
            raise ValueError("version expiry must be in the future")

        with self._transaction() as conn:
            item = self._lookup_item_by_ref(conn, ref_fp)
            self._require_owner(item, owner)
            self._require_item_active(item, ref_fp)
            scope = ScopeRef(item["scope_kind"], item["scope_id"])
            self._validate_owner_scope(owner, scope)
            injection = InjectionTarget(
                item["injection_kind"], item["injection_target"]
            )
            payload = self._validate_body(body, injection)
            row = conn.execute(
                "SELECT MAX(version) AS version FROM versions WHERE item_id = ?",
                (item["item_id"],),
            ).fetchone()
            current = int(row["version"] or 0)
            if current < 1:
                raise VaultUnavailable("reference has no material version")
            version = current + 1
            nonce = secrets.token_bytes(12)
            ciphertext = AESGCM(self._key).encrypt(
                nonce,
                payload,
                _aad(item["item_id"], version, scope, injection),
            )
            conn.execute(
                "UPDATE versions SET retired_at_ms = COALESCE(retired_at_ms, ?) "
                "WHERE item_id = ? AND version = ?",
                (now, item["item_id"], current),
            )
            conn.execute(
                """INSERT INTO versions(
                    item_id, version, nonce, ciphertext, created_at_ms,
                    expires_at_ms, retired_at_ms, revoked_at_ms
                ) VALUES (?, ?, ?, ?, ?, ?, NULL, NULL)""",
                (
                    item["item_id"],
                    version,
                    nonce,
                    ciphertext,
                    now,
                    expires_at_ms,
                ),
            )
            self._audit(
                conn,
                action="rotate",
                outcome="success",
                principal=owner,
                scope=scope,
                reference_fingerprint=ref_fp,
                version=version,
                injection=injection,
            )
        return version

    def set_expiry(
        self,
        reference: str,
        *,
        version: int,
        expires_at_ms: int | None,
        owner: PrincipalContext,
    ) -> None:
        ref_fp = _reference_fingerprint(reference)
        if isinstance(version, bool) or type(version) is not int or version < 1:
            raise ValueError("version is invalid")
        expires_at_ms = self._validate_expiry(expires_at_ms)
        now = self._now()
        if expires_at_ms is not None and expires_at_ms <= now:
            raise ValueError("version expiry must be in the future")
        with self._transaction() as conn:
            item = self._lookup_item_by_ref(conn, ref_fp)
            self._require_owner(item, owner)
            row = conn.execute(
                "SELECT 1 FROM versions WHERE item_id = ? AND version = ?",
                (item["item_id"], version),
            ).fetchone()
            if row is None:
                raise VaultUnavailable("material version is unavailable")
            conn.execute(
                "UPDATE versions SET expires_at_ms = ? WHERE item_id = ? AND version = ?",
                (expires_at_ms, item["item_id"], version),
            )
            scope = ScopeRef(item["scope_kind"], item["scope_id"])
            injection = InjectionTarget(
                item["injection_kind"], item["injection_target"]
            )
            self._audit(
                conn,
                action="set_expiry",
                outcome="success",
                principal=owner,
                scope=scope,
                reference_fingerprint=ref_fp,
                version=version,
                injection=injection,
            )

    def revoke(
        self,
        reference: str,
        *,
        owner: PrincipalContext,
        version: int | None = None,
    ) -> None:
        ref_fp = _reference_fingerprint(reference)
        if version is not None and (
            isinstance(version, bool) or type(version) is not int or version < 1
        ):
            raise ValueError("version is invalid")
        now = self._now()
        with self._transaction() as conn:
            item = self._lookup_item_by_ref(conn, ref_fp)
            self._require_owner(item, owner)
            scope = ScopeRef(item["scope_kind"], item["scope_id"])
            injection = InjectionTarget(
                item["injection_kind"], item["injection_target"]
            )
            if version is None:
                conn.execute(
                    "UPDATE items SET revoked_at_ms = COALESCE(revoked_at_ms, ?) WHERE item_id = ?",
                    (now, item["item_id"]),
                )
                conn.execute(
                    "UPDATE refs SET revoked_at_ms = COALESCE(revoked_at_ms, ?) WHERE item_id = ?",
                    (now, item["item_id"]),
                )
                conn.execute(
                    "UPDATE handles SET revoked_at_ms = COALESCE(revoked_at_ms, ?) WHERE item_id = ?",
                    (now, item["item_id"]),
                )
                audit_version = None
            else:
                row = conn.execute(
                    "SELECT 1 FROM versions WHERE item_id = ? AND version = ?",
                    (item["item_id"], version),
                ).fetchone()
                if row is None:
                    raise VaultUnavailable("material version is unavailable")
                conn.execute(
                    "UPDATE versions SET revoked_at_ms = COALESCE(revoked_at_ms, ?) "
                    "WHERE item_id = ? AND version = ?",
                    (now, item["item_id"], version),
                )
                conn.execute(
                    "UPDATE handles SET revoked_at_ms = COALESCE(revoked_at_ms, ?) "
                    "WHERE item_id = ? AND version = ?",
                    (now, item["item_id"], version),
                )
                audit_version = version
            self._audit(
                conn,
                action="revoke",
                outcome="success",
                principal=owner,
                scope=scope,
                reference_fingerprint=ref_fp,
                version=audit_version,
                injection=injection,
            )

    def inspect(self, reference: str, *, principal: PrincipalContext) -> ReferenceInfo:
        ref_fp = _reference_fingerprint(reference)
        try:
            with self._connection() as conn:
                item = self._lookup_item_by_ref(conn, ref_fp)
                scope = ScopeRef(item["scope_kind"], item["scope_id"])
                self._require_scope(scope, principal)
                version = self._latest_version(conn, item["item_id"])
                info = ReferenceInfo(
                    reference_fingerprint=ref_fp,
                    owner_principal_id=item["owner_principal_id"],
                    owner_principal_kind=item["owner_principal_kind"],
                    scope=scope,
                    injection=InjectionTarget(
                        item["injection_kind"], item["injection_target"]
                    ),
                    current_version=int(version["version"]),
                    version_expires_at_ms=version["expires_at_ms"],
                    revoked=item["revoked_at_ms"] is not None
                    or item["reference_revoked_at_ms"] is not None,
                )
            return info
        except VaultError:
            self._audit_failure(
                action="inspect",
                principal=principal,
                reference_fingerprint=ref_fp,
                detail="denied_or_unavailable",
            )
            raise

    def mint_run_handles(
        self,
        references: Iterable[str],
        *,
        run: RunContext,
        max_uses: int = _DEFAULT_MAX_USES,
    ) -> tuple[RunHandle, ...]:
        """Mint short-lived handles bound to an exact principal/run/authority."""
        if type(run) is not RunContext:
            raise ValueError("run context is invalid")
        refs = tuple(references)
        if (
            not 0 <= len(refs) <= _MAX_REFERENCES
            or any(type(reference) is not str for reference in refs)
            or len(refs) != len(set(refs))
        ):
            raise ValueError("reference set is invalid")
        if (
            isinstance(max_uses, bool)
            or type(max_uses) is not int
            or not 1 <= max_uses <= _MAX_HANDLE_USES
        ):
            raise ValueError("handle use bound is invalid")
        now = self._now()
        if run.deadline_ms <= now:
            raise VaultUnavailable("run deadline has expired")
        if not refs:
            return ()

        minted: list[RunHandle] = []
        fingerprints = tuple(_reference_fingerprint(reference) for reference in refs)
        try:
            with self._transaction() as conn:
                for reference, ref_fp in zip(refs, fingerprints, strict=True):
                    del reference
                    item = self._lookup_item_by_ref(conn, ref_fp)
                    self._require_item_active(item, ref_fp)
                    scope = ScopeRef(item["scope_kind"], item["scope_id"])
                    self._require_scope(scope, run.principal)
                    version = self._latest_version(conn, item["item_id"])
                    self._require_version_active(version, now)
                    expires_at_ms = run.deadline_ms
                    if version["expires_at_ms"] is not None:
                        expires_at_ms = min(
                            expires_at_ms, int(version["expires_at_ms"])
                        )
                    if expires_at_ms <= now:
                        raise VaultUnavailable("material version has expired")
                    injection = InjectionTarget(
                        item["injection_kind"], item["injection_target"]
                    )
                    raw_handle = _HANDLE_PREFIX + secrets.token_urlsafe(32)
                    handle_fp = _fingerprint(raw_handle)
                    conn.execute(
                        """INSERT INTO handles(
                            handle_hash, item_id, version, run_id,
                            principal_id, principal_kind, principal_generation,
                            principal_binding_hash, run_authority_hash,
                            injection_kind, injection_target, created_at_ms,
                            expires_at_ms, uses_remaining, revoked_at_ms
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)""",
                        (
                            handle_fp,
                            item["item_id"],
                            int(version["version"]),
                            run.run_id,
                            run.principal.principal_id,
                            run.principal.principal_kind,
                            run.principal.generation,
                            run.principal.binding_hash,
                            run.run_authority_hash,
                            injection.kind,
                            injection.target,
                            now,
                            expires_at_ms,
                            max_uses,
                        ),
                    )
                    self._audit(
                        conn,
                        action="mint_handle",
                        outcome="success",
                        principal=run.principal,
                        scope=scope,
                        run=run,
                        reference_fingerprint=ref_fp,
                        handle_fingerprint=handle_fp,
                        version=int(version["version"]),
                        injection=injection,
                    )
                    minted.append(
                        RunHandle(
                            handle=raw_handle,
                            injection=injection,
                            version=int(version["version"]),
                            expires_at_ms=expires_at_ms,
                        )
                    )
            return tuple(minted)
        except VaultError as error:
            for ref_fp in fingerprints:
                self._audit_failure(
                    action="mint_handle",
                    principal=run.principal,
                    run=run,
                    reference_fingerprint=ref_fp,
                    detail=type(error).__name__,
                )
            raise

    def redeem_handle(
        self,
        handle: str,
        *,
        run_id: str,
        expected_injection: InjectionTarget | None = None,
    ) -> bytes:
        """Redeem a temporary handle for trusted runtime injection only."""
        handle_fp = _handle_fingerprint(handle)
        if type(run_id) is not str or not run_id:
            raise ValueError("run id is invalid")
        if (
            expected_injection is not None
            and type(expected_injection) is not InjectionTarget
        ):
            raise ValueError("expected injection is invalid")
        now = self._now()
        try:
            with self._transaction() as conn:
                row = conn.execute(
                    """SELECT h.*, i.scope_kind, i.scope_id, i.revoked_at_ms AS item_revoked_at_ms,
                              v.nonce, v.ciphertext, v.expires_at_ms AS version_expires_at_ms,
                              v.revoked_at_ms AS version_revoked_at_ms
                       FROM handles h
                       JOIN items i ON i.item_id = h.item_id
                       JOIN versions v ON v.item_id = h.item_id AND v.version = h.version
                       WHERE h.handle_hash = ?""",
                    (handle_fp,),
                ).fetchone()
                if row is None:
                    raise VaultUnavailable("temporary run handle is unavailable")
                injection = InjectionTarget(
                    row["injection_kind"], row["injection_target"]
                )
                principal = PrincipalContext(
                    principal_id=row["principal_id"],
                    principal_kind=row["principal_kind"],
                    generation=int(row["principal_generation"]),
                    binding_hash=row["principal_binding_hash"],
                    scopes=(ScopeRef(row["scope_kind"], row["scope_id"]),),
                )
                run = RunContext(
                    principal=principal,
                    run_id=row["run_id"],
                    run_authority_hash=row["run_authority_hash"],
                    deadline_ms=int(row["expires_at_ms"]),
                )
                if row["run_id"] != run_id:
                    raise VaultAccessDenied(
                        "temporary run handle belongs to another run"
                    )
                if expected_injection is not None and injection != expected_injection:
                    raise VaultAccessDenied(
                        "temporary run handle injection target changed"
                    )
                if (
                    row["revoked_at_ms"] is not None
                    or row["item_revoked_at_ms"] is not None
                    or row["version_revoked_at_ms"] is not None
                ):
                    raise VaultUnavailable("temporary run handle is revoked")
                if int(row["expires_at_ms"]) <= now:
                    raise VaultUnavailable("temporary run handle has expired")
                if (
                    row["version_expires_at_ms"] is not None
                    and int(row["version_expires_at_ms"]) <= now
                ):
                    raise VaultUnavailable("material version has expired")
                uses = int(row["uses_remaining"])
                if uses < 1:
                    raise VaultUnavailable(
                        "temporary run handle use bound is exhausted"
                    )
                conn.execute(
                    "UPDATE handles SET uses_remaining = uses_remaining - 1 WHERE handle_hash = ?",
                    (handle_fp,),
                )
                scope = ScopeRef(row["scope_kind"], row["scope_id"])
                aad = _aad(row["item_id"], int(row["version"]), scope, injection)
                try:
                    payload = AESGCM(self._key).decrypt(
                        bytes(row["nonce"]), bytes(row["ciphertext"]), aad
                    )
                except Exception as error:
                    raise VaultUnavailable("material decryption failed") from error
                self._validate_body(payload, injection)
                self._audit(
                    conn,
                    action="redeem_handle",
                    outcome="success",
                    principal=principal,
                    scope=scope,
                    run=run,
                    handle_fingerprint=handle_fp,
                    version=int(row["version"]),
                    injection=injection,
                )
            return payload
        except VaultError as error:
            self._audit_failure(
                action="redeem_handle",
                run_id=run_id,
                handle_fingerprint=handle_fp,
                detail=type(error).__name__,
            )
            raise

    def redeem_text(
        self,
        handle: str,
        *,
        run_id: str,
        expected_injection: InjectionTarget | None = None,
    ) -> str:
        payload = self.redeem_handle(
            handle,
            run_id=run_id,
            expected_injection=expected_injection,
        )
        try:
            return payload.decode("utf-8")
        except UnicodeDecodeError as error:
            raise VaultUnavailable("material is not UTF-8 text") from error

    def revoke_run(self, run_id: str) -> int:
        if type(run_id) is not str or not run_id:
            raise ValueError("run id is invalid")
        now = self._now()
        with self._transaction() as conn:
            rows = conn.execute(
                "SELECT handle_hash FROM handles WHERE run_id = ? AND revoked_at_ms IS NULL",
                (run_id,),
            ).fetchall()
            conn.execute(
                "UPDATE handles SET revoked_at_ms = ? WHERE run_id = ? AND revoked_at_ms IS NULL",
                (now, run_id),
            )
            self._audit(
                conn,
                action="revoke_run",
                outcome="success",
                run_id=run_id,
                detail=f"handles={len(rows)}",
            )
        return len(rows)

    def audit_records(self, *, limit: int = 100) -> tuple[AuditRecord, ...]:
        if isinstance(limit, bool) or type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("audit limit is invalid")
        with self._connection() as conn:
            rows = conn.execute(
                """SELECT timestamp_ms, action, outcome, principal_id, principal_kind,
                          scope_kind, scope_id, run_id, run_authority_hash,
                          reference_fingerprint, handle_fingerprint, version,
                          injection_kind, injection_target, detail
                   FROM audit ORDER BY id DESC LIMIT ?""",
                (limit,),
            ).fetchall()
        return tuple(
            AuditRecord(
                timestamp_ms=int(row["timestamp_ms"]),
                action=row["action"],
                outcome=row["outcome"],
                principal_id=row["principal_id"],
                principal_kind=row["principal_kind"],
                scope_kind=row["scope_kind"],
                scope_id=row["scope_id"],
                run_id=row["run_id"],
                run_authority_hash=row["run_authority_hash"],
                reference_fingerprint=row["reference_fingerprint"],
                handle_fingerprint=row["handle_fingerprint"],
                version=row["version"],
                injection_kind=row["injection_kind"],
                injection_target=row["injection_target"],
                detail=row["detail"],
            )
            for row in rows
        )

    def _prepare_root(self) -> None:
        if self._root.exists() or self._root.is_symlink():
            info = self._root.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise VaultError("store root is unsafe")
            if os.name != "nt" and stat.S_IMODE(info.st_mode) & 0o077:
                raise VaultError("store root permissions are too broad")
            geteuid = getattr(os, "geteuid", None)
            if geteuid is not None and info.st_uid != geteuid():
                raise VaultError("store root is owned by another user")
            return
        self._root.mkdir(parents=True, mode=0o700)
        if os.name != "nt":
            self._root.chmod(0o700)

    def _load_or_create_key(self) -> bytes:
        path = self._root / "master.key"
        if path.exists() or path.is_symlink():
            if path.is_symlink() or not path.is_file():
                raise VaultError("master key path is unsafe")
            info = path.stat()
            if os.name != "nt" and stat.S_IMODE(info.st_mode) != 0o600:
                raise VaultError("master key permissions are unsafe")
            payload = path.read_bytes()
            if len(payload) != 32:
                raise VaultError("master key is invalid")
            return payload
        key = secrets.token_bytes(32)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags, 0o600)
        try:
            os.write(descriptor, key)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        if os.name != "nt":
            path.chmod(0o600)
        return key

    def _initialize_database(self) -> None:
        old_umask = os.umask(0o177) if os.name != "nt" else None
        try:
            with self._connection() as conn:
                conn.executescript(
                    """
                    PRAGMA foreign_keys = ON;
                    PRAGMA journal_mode = DELETE;
                    PRAGMA synchronous = FULL;
                    CREATE TABLE IF NOT EXISTS items(
                        item_id TEXT PRIMARY KEY,
                        owner_principal_id TEXT NOT NULL,
                        owner_principal_kind TEXT NOT NULL,
                        scope_kind TEXT NOT NULL,
                        scope_id TEXT NOT NULL,
                        injection_kind TEXT NOT NULL,
                        injection_target TEXT NOT NULL,
                        created_at_ms INTEGER NOT NULL,
                        revoked_at_ms INTEGER
                    );
                    CREATE TABLE IF NOT EXISTS versions(
                        item_id TEXT NOT NULL REFERENCES items(item_id) ON DELETE CASCADE,
                        version INTEGER NOT NULL,
                        nonce BLOB NOT NULL,
                        ciphertext BLOB NOT NULL,
                        created_at_ms INTEGER NOT NULL,
                        expires_at_ms INTEGER,
                        retired_at_ms INTEGER,
                        revoked_at_ms INTEGER,
                        PRIMARY KEY(item_id, version)
                    );
                    CREATE TABLE IF NOT EXISTS refs(
                        reference_hash TEXT PRIMARY KEY,
                        item_id TEXT NOT NULL REFERENCES items(item_id) ON DELETE CASCADE,
                        created_at_ms INTEGER NOT NULL,
                        revoked_at_ms INTEGER
                    );
                    CREATE TABLE IF NOT EXISTS handles(
                        handle_hash TEXT PRIMARY KEY,
                        item_id TEXT NOT NULL REFERENCES items(item_id) ON DELETE CASCADE,
                        version INTEGER NOT NULL,
                        run_id TEXT NOT NULL,
                        principal_id TEXT NOT NULL,
                        principal_kind TEXT NOT NULL,
                        principal_generation INTEGER NOT NULL,
                        principal_binding_hash TEXT NOT NULL,
                        run_authority_hash TEXT NOT NULL,
                        injection_kind TEXT NOT NULL,
                        injection_target TEXT NOT NULL,
                        created_at_ms INTEGER NOT NULL,
                        expires_at_ms INTEGER NOT NULL,
                        uses_remaining INTEGER NOT NULL,
                        revoked_at_ms INTEGER,
                        FOREIGN KEY(item_id, version) REFERENCES versions(item_id, version)
                    );
                    CREATE INDEX IF NOT EXISTS handles_run_id_idx ON handles(run_id);
                    CREATE TABLE IF NOT EXISTS audit(
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp_ms INTEGER NOT NULL,
                        action TEXT NOT NULL,
                        outcome TEXT NOT NULL,
                        principal_id TEXT,
                        principal_kind TEXT,
                        scope_kind TEXT,
                        scope_id TEXT,
                        run_id TEXT,
                        run_authority_hash TEXT,
                        reference_fingerprint TEXT,
                        handle_fingerprint TEXT,
                        version INTEGER,
                        injection_kind TEXT,
                        injection_target TEXT,
                        detail TEXT
                    );
                    """
                )
        finally:
            if old_umask is not None:
                os.umask(old_umask)
        if os.name != "nt":
            self._db_path.chmod(0o600)

    def _connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            self._db_path,
            timeout=10.0,
            isolation_level=None,
            check_same_thread=False,
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA busy_timeout = 10000")
        return conn

    def _transaction(self):
        return _Transaction(self)

    def _lookup_item_by_ref(self, conn: sqlite3.Connection, ref_fp: str) -> sqlite3.Row:
        row = conn.execute(
            """SELECT i.*, r.revoked_at_ms AS reference_revoked_at_ms
               FROM refs r JOIN items i ON i.item_id = r.item_id
               WHERE r.reference_hash = ?""",
            (ref_fp,),
        ).fetchone()
        if row is None:
            raise VaultUnavailable("opaque reference is unavailable")
        return row

    def _latest_version(self, conn: sqlite3.Connection, item_id: str) -> sqlite3.Row:
        row = conn.execute(
            "SELECT * FROM versions WHERE item_id = ? ORDER BY version DESC LIMIT 1",
            (item_id,),
        ).fetchone()
        if row is None:
            raise VaultUnavailable("material version is unavailable")
        return row

    def _require_item_active(self, item: sqlite3.Row, ref_fp: str) -> None:
        del ref_fp
        if (
            item["revoked_at_ms"] is not None
            or item["reference_revoked_at_ms"] is not None
        ):
            raise VaultUnavailable("opaque reference is revoked")

    def _require_version_active(self, version: sqlite3.Row, now: int) -> None:
        if version["revoked_at_ms"] is not None:
            raise VaultUnavailable("material version is revoked")
        if (
            version["expires_at_ms"] is not None
            and int(version["expires_at_ms"]) <= now
        ):
            raise VaultUnavailable("material version has expired")

    def _require_owner(self, item: sqlite3.Row, owner: PrincipalContext) -> None:
        if type(owner) is not PrincipalContext:
            raise ValueError("owner principal is invalid")
        if (
            item["owner_principal_id"] != owner.principal_id
            or item["owner_principal_kind"] != owner.principal_kind
        ):
            raise VaultAccessDenied("current principal does not own this reference")

    def _require_scope(self, scope: ScopeRef, principal: PrincipalContext) -> None:
        if type(principal) is not PrincipalContext:
            raise ValueError("principal context is invalid")
        if scope not in principal.scopes:
            raise VaultAccessDenied(
                "reference scope is not authorized for this principal/run"
            )

    def _validate_owner_scope(self, owner: PrincipalContext, scope: ScopeRef) -> None:
        if type(owner) is not PrincipalContext or type(scope) is not ScopeRef:
            raise ValueError("owner scope is invalid")
        self._require_scope(scope, owner)

    def _validate_body(self, body: str | bytes, injection: InjectionTarget) -> bytes:
        if type(injection) is not InjectionTarget:
            raise ValueError("injection target is invalid")
        if type(body) is str:
            payload = body.encode("utf-8")
        elif type(body) is bytes:
            payload = body
        else:
            raise ValueError("material body must be text or bytes")
        if not payload or len(payload) > _MAX_BODY_BYTES:
            raise ValueError("material body exceeds the supported bound")
        if injection.kind == "env":
            if len(payload) > _MAX_ENV_BYTES:
                raise ValueError("environment material exceeds the supported bound")
            try:
                value = payload.decode("utf-8")
            except UnicodeDecodeError as error:
                raise ValueError("environment material must be UTF-8 text") from error
            if any(character in value for character in ("\x00", "\n", "\r")):
                raise ValueError(
                    "environment material contains forbidden control characters"
                )
        return payload

    @staticmethod
    def _validate_expiry(value: int | None) -> int | None:
        if value is None:
            return None
        if isinstance(value, bool) or type(value) is not int or value < 1:
            raise ValueError("expiry is invalid")
        return value

    def _now(self) -> int:
        value = self._now_ms()
        if isinstance(value, bool) or type(value) is not int or value < 1:
            raise VaultError("store clock returned an invalid timestamp")
        return value

    def _audit(
        self,
        conn: sqlite3.Connection,
        *,
        action: str,
        outcome: str,
        principal: PrincipalContext | None = None,
        scope: ScopeRef | None = None,
        run: RunContext | None = None,
        run_id: str | None = None,
        reference_fingerprint: str | None = None,
        handle_fingerprint: str | None = None,
        version: int | None = None,
        injection: InjectionTarget | None = None,
        detail: str | None = None,
    ) -> None:
        conn.execute(
            """INSERT INTO audit(
                timestamp_ms, action, outcome, principal_id, principal_kind,
                scope_kind, scope_id, run_id, run_authority_hash,
                reference_fingerprint, handle_fingerprint, version,
                injection_kind, injection_target, detail
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                self._now(),
                action,
                outcome,
                principal.principal_id if principal else None,
                principal.principal_kind if principal else None,
                scope.kind if scope else None,
                scope.scope_id if scope else None,
                run.run_id if run else run_id,
                run.run_authority_hash if run else None,
                reference_fingerprint,
                handle_fingerprint,
                version,
                injection.kind if injection else None,
                injection.target if injection else None,
                detail,
            ),
        )

    def _audit_failure(
        self,
        *,
        action: str,
        principal: PrincipalContext | None = None,
        run: RunContext | None = None,
        run_id: str | None = None,
        reference_fingerprint: str | None = None,
        handle_fingerprint: str | None = None,
        detail: str,
    ) -> None:
        try:
            with self._transaction() as conn:
                self._audit(
                    conn,
                    action=action,
                    outcome="denied",
                    principal=principal,
                    run=run,
                    run_id=run_id,
                    reference_fingerprint=reference_fingerprint,
                    handle_fingerprint=handle_fingerprint,
                    detail=detail,
                )
        except Exception:
            # Auditing must never turn a denial into accidental access.
            pass


class _Transaction:
    def __init__(self, store: VaultStore) -> None:
        self._store = store
        self._conn: sqlite3.Connection | None = None

    def __enter__(self) -> sqlite3.Connection:
        self._store._lock.acquire()
        self._conn = self._store._connection()
        self._conn.execute("BEGIN IMMEDIATE")
        return self._conn

    def __exit__(self, exc_type, exc, tb) -> bool:
        assert self._conn is not None
        try:
            if exc_type is None:
                self._conn.execute("COMMIT")
            else:
                self._conn.execute("ROLLBACK")
        finally:
            self._conn.close()
            self._store._lock.release()
        return False


def default_store_root() -> Path:
    configured = os.environ.get("HERMES_VAULT_HOME")
    if configured:
        return Path(configured).expanduser().absolute()
    return (Path.home() / ".hermes-vault").absolute()


def open_default_store(*, now_ms: Callable[[], int] | None = None) -> VaultStore:
    return VaultStore(default_store_root(), now_ms=now_ms)


def _fingerprint(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _reference_fingerprint(reference: str) -> str:
    if (
        type(reference) is not str
        or not reference.startswith(_REFERENCE_PREFIX)
        or not 20 <= len(reference) <= 160
    ):
        raise VaultUnavailable("opaque reference is invalid")
    return _fingerprint(reference)


def _handle_fingerprint(handle: str) -> str:
    if (
        type(handle) is not str
        or not handle.startswith(_HANDLE_PREFIX)
        or not 20 <= len(handle) <= 160
    ):
        raise VaultUnavailable("temporary run handle is invalid")
    return _fingerprint(handle)


def _aad(
    item_id: str,
    version: int,
    scope: ScopeRef,
    injection: InjectionTarget,
) -> bytes:
    return json.dumps(
        {
            "item_id": item_id,
            "version": version,
            "scope": scope.to_dict(),
            "injection": injection.to_dict(),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
