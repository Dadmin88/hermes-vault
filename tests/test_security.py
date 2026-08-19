from __future__ import annotations

import os
from pathlib import Path

import pytest

from hermes_secure_store import VaultError, VaultStore


def test_existing_posix_root_with_broad_permissions_is_rejected(tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("POSIX permission invariant")
    root = tmp_path / "unsafe"
    root.mkdir(mode=0o755)
    root.chmod(0o755)
    with pytest.raises(VaultError, match="permissions"):
        VaultStore(root.absolute())


def test_symlink_root_is_rejected(tmp_path: Path) -> None:
    if not hasattr(os, "symlink"):
        pytest.skip("symlinks unavailable")
    target = tmp_path / "target"
    target.mkdir(mode=0o700)
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=True)
    with pytest.raises(VaultError, match="unsafe"):
        VaultStore(link.absolute())
