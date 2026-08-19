from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from .models import InjectionTarget, PrincipalContext, ScopeRef, VaultError
from .store import VaultStore, default_store_root


def _scope(value: str) -> ScopeRef:
    kind, separator, scope_id = value.partition(":")
    if not separator:
        raise argparse.ArgumentTypeError("scope must be kind:id")
    try:
        return ScopeRef(kind, scope_id)
    except ValueError as error:
        raise argparse.ArgumentTypeError(str(error)) from error


def _injection(value: str) -> InjectionTarget:
    kind, separator, target = value.partition(":")
    if not separator:
        raise argparse.ArgumentTypeError("injection must be kind:target")
    try:
        return InjectionTarget(kind, target)
    except ValueError as error:
        raise argparse.ArgumentTypeError(str(error)) from error


def _add_principal(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--principal-id", required=True)
    parser.add_argument("--principal-kind", default="owner")
    parser.add_argument("--generation", type=int, default=1)
    parser.add_argument("--binding-hash", required=True)
    parser.add_argument("--scope", action="append", type=_scope, default=[])


def _principal(args: argparse.Namespace) -> PrincipalContext:
    return PrincipalContext(
        principal_id=args.principal_id,
        principal_kind=args.principal_kind,
        generation=args.generation,
        binding_hash=args.binding_hash,
        scopes=tuple(args.scope),
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hermes-vault",
        description="Hermes scoped material custody. Bodies are accepted via stdin only.",
    )
    parser.add_argument("--root", type=Path, default=default_store_root())
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init", help="initialize the encrypted local store")
    del init

    put = sub.add_parser("put", help="create an opaque reference from stdin")
    _add_principal(put)
    put.add_argument("--target-scope", required=True, type=_scope)
    put.add_argument("--inject", required=True, type=_injection)
    put.add_argument("--expires-at-ms", type=int)

    rotate = sub.add_parser("rotate", help="rotate a reference from stdin")
    _add_principal(rotate)
    rotate.add_argument("reference")
    rotate.add_argument("--expires-at-ms", type=int)

    revoke = sub.add_parser("revoke", help="revoke a reference or one version")
    _add_principal(revoke)
    revoke.add_argument("reference")
    revoke.add_argument("--version", type=int)

    inspect = sub.add_parser("inspect", help="inspect value-free reference metadata")
    _add_principal(inspect)
    inspect.add_argument("reference")

    audit = sub.add_parser("audit", help="show value-free access audit records")
    audit.add_argument("--limit", type=int, default=50)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        custody = VaultStore(args.root.expanduser().absolute())
        if args.command == "init":
            print(json.dumps({"ok": True, "root": str(custody.root)}))
            return 0
        if args.command == "put":
            body = sys.stdin.buffer.read()
            reference = custody.put(
                body,
                owner=_principal(args),
                scope=args.target_scope,
                injection=args.inject,
                expires_at_ms=args.expires_at_ms,
            )
            print(reference)
            return 0
        if args.command == "rotate":
            body = sys.stdin.buffer.read()
            version = custody.rotate(
                args.reference,
                body,
                owner=_principal(args),
                expires_at_ms=args.expires_at_ms,
            )
            print(json.dumps({"ok": True, "version": version}))
            return 0
        if args.command == "revoke":
            custody.revoke(
                args.reference,
                owner=_principal(args),
                version=args.version,
            )
            print(json.dumps({"ok": True}))
            return 0
        if args.command == "inspect":
            info = custody.inspect(args.reference, principal=_principal(args))
            print(
                json.dumps(
                    {
                        "reference_fingerprint": info.reference_fingerprint,
                        "owner_principal_id": info.owner_principal_id,
                        "owner_principal_kind": info.owner_principal_kind,
                        "scope": info.scope.to_dict(),
                        "injection": info.injection.to_dict(),
                        "current_version": info.current_version,
                        "version_expires_at_ms": info.version_expires_at_ms,
                        "revoked": info.revoked,
                    },
                    sort_keys=True,
                )
            )
            return 0
        if args.command == "audit":
            rows = [
                asdict(record) for record in custody.audit_records(limit=args.limit)
            ]
            print(json.dumps(rows, sort_keys=True))
            return 0
    except (ValueError, VaultError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
