from __future__ import annotations

import re
from dataclasses import dataclass

_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,511}$")
_ENV_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
_FILE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_BROKER_RE = re.compile(r"^[a-z][a-z0-9_.:-]{0,127}$")
_SCOPE_KINDS = frozenset({"principal", "project", "network", "owner"})
_PRINCIPAL_KINDS = frozenset({"owner", "project", "network", "device", "service"})
_INJECTION_KINDS = frozenset({"env", "file", "broker"})


class VaultError(RuntimeError):
    """Stable public error for scoped material custody failures."""


class VaultAccessDenied(VaultError):
    """The current principal/run may not use the requested reference."""


class VaultUnavailable(VaultError):
    """The requested reference, version or temporary handle is unavailable."""


@dataclass(frozen=True, slots=True, order=True)
class ScopeRef:
    kind: str
    scope_id: str

    def __post_init__(self) -> None:
        if self.kind not in _SCOPE_KINDS:
            raise ValueError("scope kind is invalid")
        if (
            type(self.scope_id) is not str
            or _IDENTIFIER_RE.fullmatch(self.scope_id) is None
        ):
            raise ValueError("scope id is invalid")

    def to_dict(self) -> dict[str, str]:
        return {"kind": self.kind, "scope_id": self.scope_id}


@dataclass(frozen=True, slots=True)
class PrincipalContext:
    principal_id: str
    principal_kind: str
    generation: int
    binding_hash: str
    scopes: tuple[ScopeRef, ...] = ()

    def __post_init__(self) -> None:
        if (
            type(self.principal_id) is not str
            or _HASH_RE.fullmatch(self.principal_id) is None
        ):
            raise ValueError("principal id is invalid")
        if self.principal_kind not in _PRINCIPAL_KINDS:
            raise ValueError("principal kind is invalid")
        if (
            isinstance(self.generation, bool)
            or type(self.generation) is not int
            or self.generation < 1
        ):
            raise ValueError("principal generation is invalid")
        if (
            type(self.binding_hash) is not str
            or _HASH_RE.fullmatch(self.binding_hash) is None
        ):
            raise ValueError("principal binding hash is invalid")
        scopes = tuple(self.scopes)
        if any(type(scope) is not ScopeRef for scope in scopes) or len(scopes) != len(
            set(scopes)
        ):
            raise ValueError("principal scopes are invalid")
        principal_scope = ScopeRef("principal", self.principal_id)
        if principal_scope not in scopes:
            scopes = (principal_scope, *scopes)
        object.__setattr__(self, "scopes", tuple(sorted(set(scopes))))


@dataclass(frozen=True, slots=True)
class RunContext:
    principal: PrincipalContext
    run_id: str
    run_authority_hash: str
    deadline_ms: int

    def __post_init__(self) -> None:
        if type(self.principal) is not PrincipalContext:
            raise ValueError("run principal is invalid")
        if (
            type(self.run_id) is not str
            or _IDENTIFIER_RE.fullmatch(self.run_id) is None
        ):
            raise ValueError("run id is invalid")
        if (
            type(self.run_authority_hash) is not str
            or _HASH_RE.fullmatch(self.run_authority_hash) is None
        ):
            raise ValueError("run authority hash is invalid")
        if (
            isinstance(self.deadline_ms, bool)
            or type(self.deadline_ms) is not int
            or self.deadline_ms < 1
        ):
            raise ValueError("run deadline is invalid")


@dataclass(frozen=True, slots=True)
class InjectionTarget:
    kind: str
    target: str

    def __post_init__(self) -> None:
        if self.kind not in _INJECTION_KINDS:
            raise ValueError("injection kind is invalid")
        if type(self.target) is not str:
            raise ValueError("injection target is invalid")
        matcher = {"env": _ENV_RE, "file": _FILE_RE, "broker": _BROKER_RE}[self.kind]
        if matcher.fullmatch(self.target) is None:
            raise ValueError("injection target is invalid")

    def to_dict(self) -> dict[str, str]:
        return {"kind": self.kind, "target": self.target}


@dataclass(frozen=True, slots=True, repr=False)
class RunHandle:
    handle: str
    injection: InjectionTarget
    version: int
    expires_at_ms: int

    def __post_init__(self) -> None:
        if (
            type(self.handle) is not str
            or not self.handle.startswith("hvh1_")
            or len(self.handle) > 160
        ):
            raise ValueError("run handle is invalid")
        if type(self.injection) is not InjectionTarget:
            raise ValueError("run handle injection is invalid")
        if (
            isinstance(self.version, bool)
            or type(self.version) is not int
            or self.version < 1
        ):
            raise ValueError("run handle version is invalid")
        if (
            isinstance(self.expires_at_ms, bool)
            or type(self.expires_at_ms) is not int
            or self.expires_at_ms < 1
        ):
            raise ValueError("run handle expiry is invalid")

    def __repr__(self) -> str:
        return (
            "RunHandle(<opaque>, injection="
            f"{self.injection.kind}:{self.injection.target}, version={self.version})"
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "handle": self.handle,
            "injection": self.injection.to_dict(),
            "version": self.version,
            "expires_at_ms": self.expires_at_ms,
        }


@dataclass(frozen=True, slots=True)
class ReferenceInfo:
    reference_fingerprint: str
    owner_principal_id: str
    owner_principal_kind: str
    scope: ScopeRef
    injection: InjectionTarget
    current_version: int
    version_expires_at_ms: int | None
    revoked: bool


@dataclass(frozen=True, slots=True)
class AuditRecord:
    timestamp_ms: int
    action: str
    outcome: str
    principal_id: str | None
    principal_kind: str | None
    scope_kind: str | None
    scope_id: str | None
    run_id: str | None
    run_authority_hash: str | None
    reference_fingerprint: str | None
    handle_fingerprint: str | None
    version: int | None
    injection_kind: str | None
    injection_target: str | None
    detail: str | None
