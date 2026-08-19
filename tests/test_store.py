from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from hermes_secure_store import (
    InjectionTarget,
    PrincipalContext,
    RunContext,
    ScopeRef,
    VaultAccessDenied,
    VaultStore,
    VaultUnavailable,
)

P1 = "sha256:" + "1" * 64
P2 = "sha256:" + "2" * 64
B1 = "sha256:" + "3" * 64
B2 = "sha256:" + "4" * 64
AUTH = "sha256:" + "5" * 64
PROJECT = ScopeRef("project", "project-alpha")
NETWORK = ScopeRef("network", "network-alpha")
OWNER = ScopeRef("owner", "owner-alpha")


def principal(
    principal_id: str = P1,
    *,
    binding: str = B1,
    scopes: tuple[ScopeRef, ...] = (),
) -> PrincipalContext:
    return PrincipalContext(
        principal_id=principal_id,
        principal_kind="owner",
        generation=1,
        binding_hash=binding,
        scopes=scopes,
    )


def run(
    who: PrincipalContext,
    *,
    run_id: str = "run-one",
    deadline_ms: int = 10_000,
) -> RunContext:
    return RunContext(
        principal=who,
        run_id=run_id,
        run_authority_hash=AUTH,
        deadline_ms=deadline_ms,
    )


def store(tmp_path: Path, clock: list[int]) -> VaultStore:
    root = tmp_path / "custody"
    return VaultStore(root.absolute(), now_ms=lambda: clock[0])


def test_body_is_encrypted_and_reference_is_opaque(tmp_path: Path) -> None:
    clock = [1_000]
    custody = store(tmp_path, clock)
    body = "provider-value-very-private-1234567890"
    reference = custody.put(
        body,
        owner=principal(),
        scope=ScopeRef("principal", P1),
        injection=InjectionTarget("env", "PROVIDER_KEY"),
    )

    assert reference.startswith("hvr1_")
    assert P1 not in reference
    root = custody.root
    for path in root.iterdir():
        if path.is_file():
            payload = path.read_bytes()
            assert body.encode() not in payload
            assert reference.encode() not in payload
    if os.name != "nt":
        assert stat.S_IMODE(root.stat().st_mode) == 0o700
        assert stat.S_IMODE((root / "master.key").stat().st_mode) == 0o600
        assert stat.S_IMODE((root / "state.db").stat().st_mode) == 0o600


def test_project_and_network_scope_are_explicit_not_owner_inference(
    tmp_path: Path,
) -> None:
    clock = [1_000]
    custody = store(tmp_path, clock)
    owner = principal(scopes=(PROJECT, NETWORK, OWNER))
    project_ref = custody.put(
        "project-value",
        owner=owner,
        scope=PROJECT,
        injection=InjectionTarget("env", "PROJECT_KEY"),
    )
    network_ref = custody.put(
        "network-value",
        owner=owner,
        scope=NETWORK,
        injection=InjectionTarget("broker", "network.auth"),
    )

    other_without_scope = principal(P2, binding=B2)
    with pytest.raises(VaultAccessDenied, match="scope"):
        custody.mint_run_handles((project_ref,), run=run(other_without_scope))

    project_member = principal(P2, binding=B2, scopes=(PROJECT,))
    handles = custody.mint_run_handles((project_ref,), run=run(project_member))
    assert len(handles) == 1
    assert handles[0].injection == InjectionTarget("env", "PROJECT_KEY")

    network_member = principal(P2, binding=B2, scopes=(NETWORK,))
    handle = custody.mint_run_handles((network_ref,), run=run(network_member))[0]
    assert custody.redeem_text(handle.handle, run_id="run-one") == "network-value"


def test_only_owner_can_rotate_or_revoke(tmp_path: Path) -> None:
    clock = [1_000]
    custody = store(tmp_path, clock)
    owner = principal(scopes=(PROJECT,))
    reference = custody.put(
        "v1",
        owner=owner,
        scope=PROJECT,
        injection=InjectionTarget("env", "PROJECT_KEY"),
    )
    project_member = principal(P2, binding=B2, scopes=(PROJECT,))

    with pytest.raises(VaultAccessDenied, match="own"):
        custody.rotate(reference, "v2", owner=project_member)
    with pytest.raises(VaultAccessDenied, match="own"):
        custody.revoke(reference, owner=project_member)

    assert custody.rotate(reference, "v2", owner=owner) == 2
    custody.revoke(reference, owner=owner)
    with pytest.raises(VaultUnavailable, match="revoked"):
        custody.mint_run_handles((reference,), run=run(owner))


def test_rotation_pins_existing_handle_and_new_handle_uses_latest(
    tmp_path: Path,
) -> None:
    clock = [1_000]
    custody = store(tmp_path, clock)
    owner = principal()
    reference = custody.put(
        "old-value",
        owner=owner,
        scope=ScopeRef("principal", P1),
        injection=InjectionTarget("env", "PROVIDER_KEY"),
    )
    old_handle = custody.mint_run_handles((reference,), run=run(owner))[0]
    assert old_handle.version == 1

    assert custody.rotate(reference, "new-value", owner=owner) == 2
    new_handle = custody.mint_run_handles(
        (reference,), run=run(owner, run_id="run-two")
    )[0]
    assert new_handle.version == 2

    assert custody.redeem_text(old_handle.handle, run_id="run-one") == "old-value"
    assert custody.redeem_text(new_handle.handle, run_id="run-two") == "new-value"


def test_expiry_version_revocation_and_run_revocation_fail_closed(
    tmp_path: Path,
) -> None:
    clock = [1_000]
    custody = store(tmp_path, clock)
    owner = principal()
    reference = custody.put(
        "expiring-value",
        owner=owner,
        scope=ScopeRef("principal", P1),
        injection=InjectionTarget("env", "PROVIDER_KEY"),
        expires_at_ms=2_000,
    )
    handle = custody.mint_run_handles((reference,), run=run(owner, deadline_ms=5_000))[
        0
    ]
    assert handle.expires_at_ms == 2_000

    clock[0] = 2_000
    with pytest.raises(VaultUnavailable, match="expired"):
        custody.redeem_handle(handle.handle, run_id="run-one")
    with pytest.raises(VaultUnavailable, match="expired"):
        custody.mint_run_handles((reference,), run=run(owner, deadline_ms=5_000))

    clock[0] = 3_000
    reference = custody.put(
        "versioned",
        owner=owner,
        scope=ScopeRef("principal", P1),
        injection=InjectionTarget("broker", "provider.auth"),
    )
    handle = custody.mint_run_handles(
        (reference,), run=run(owner, run_id="run-revoke", deadline_ms=9_000)
    )[0]
    custody.revoke(reference, owner=owner, version=1)
    with pytest.raises(VaultUnavailable, match="revoked"):
        custody.redeem_handle(handle.handle, run_id="run-revoke")

    reference = custody.put(
        "run-scoped",
        owner=owner,
        scope=ScopeRef("principal", P1),
        injection=InjectionTarget("env", "RUN_KEY"),
    )
    handle = custody.mint_run_handles(
        (reference,), run=run(owner, run_id="run-cleanup", deadline_ms=9_000)
    )[0]
    assert custody.revoke_run("run-cleanup") == 1
    with pytest.raises(VaultUnavailable, match="revoked"):
        custody.redeem_handle(handle.handle, run_id="run-cleanup")


def test_handle_is_bound_to_exact_run_target_and_use_budget(tmp_path: Path) -> None:
    clock = [1_000]
    custody = store(tmp_path, clock)
    owner = principal()
    reference = custody.put(
        "value",
        owner=owner,
        scope=ScopeRef("principal", P1),
        injection=InjectionTarget("env", "PROVIDER_KEY"),
    )
    handle = custody.mint_run_handles((reference,), run=run(owner), max_uses=1)[0]

    with pytest.raises(VaultAccessDenied, match="another run"):
        custody.redeem_handle(handle.handle, run_id="wrong-run")
    with pytest.raises(VaultAccessDenied, match="target changed"):
        custody.redeem_handle(
            handle.handle,
            run_id="run-one",
            expected_injection=InjectionTarget("env", "OTHER_KEY"),
        )
    assert (
        custody.redeem_text(
            handle.handle,
            run_id="run-one",
            expected_injection=InjectionTarget("env", "PROVIDER_KEY"),
        )
        == "value"
    )
    with pytest.raises(VaultUnavailable, match="use bound"):
        custody.redeem_handle(handle.handle, run_id="run-one")


def test_file_and_broker_material_cross_process_store_instances(tmp_path: Path) -> None:
    clock = [1_000]
    first = store(tmp_path, clock)
    owner = principal()
    file_ref = first.put(
        b"\x00binary\nfile-body",
        owner=owner,
        scope=ScopeRef("principal", P1),
        injection=InjectionTarget("file", "service.pem"),
    )
    broker_ref = first.put(
        "broker-value",
        owner=owner,
        scope=ScopeRef("principal", P1),
        injection=InjectionTarget("broker", "service.auth"),
    )
    handles = first.mint_run_handles((file_ref, broker_ref), run=run(owner))

    second = VaultStore(first.root, now_ms=lambda: clock[0])
    by_kind = {handle.injection.kind: handle for handle in handles}
    assert (
        second.redeem_handle(
            by_kind["file"].handle,
            run_id="run-one",
            expected_injection=InjectionTarget("file", "service.pem"),
        )
        == b"\x00binary\nfile-body"
    )
    assert (
        second.redeem_text(
            by_kind["broker"].handle,
            run_id="run-one",
            expected_injection=InjectionTarget("broker", "service.auth"),
        )
        == "broker-value"
    )


def test_audit_is_value_free_and_uses_fingerprints(tmp_path: Path) -> None:
    clock = [1_000]
    custody = store(tmp_path, clock)
    owner = principal()
    body = "audit-body-must-never-appear"
    reference = custody.put(
        body,
        owner=owner,
        scope=ScopeRef("principal", P1),
        injection=InjectionTarget("env", "PROVIDER_KEY"),
    )
    handle = custody.mint_run_handles((reference,), run=run(owner))[0]
    assert custody.redeem_text(handle.handle, run_id="run-one") == body
    records = custody.audit_records(limit=20)
    assert records
    rendered = repr(records)
    assert body not in rendered
    assert reference not in rendered
    assert handle.handle not in rendered
    assert any(record.reference_fingerprint for record in records)
    assert any(record.handle_fingerprint for record in records)


def test_environment_material_rejects_multiline_and_binary(tmp_path: Path) -> None:
    clock = [1_000]
    custody = store(tmp_path, clock)
    owner = principal()
    with pytest.raises(ValueError, match="control characters"):
        custody.put(
            "line-one\nline-two",
            owner=owner,
            scope=ScopeRef("principal", P1),
            injection=InjectionTarget("env", "PROVIDER_KEY"),
        )
    with pytest.raises(ValueError, match="UTF-8"):
        custody.put(
            b"\xff\xfe",
            owner=owner,
            scope=ScopeRef("principal", P1),
            injection=InjectionTarget("env", "PROVIDER_KEY"),
        )
