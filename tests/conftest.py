import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from vault.core import Vault  # noqa: E402


@pytest.fixture
def env(tmp_path):
    """A freshly initialised 3-of-5 vault: (data dir, hex shares, root token). Still sealed."""
    d = tmp_path / "v"
    shares, root = Vault.init(d, 5, 3)
    return d, shares, root


@pytest.fixture
def unsealed(env):
    d, shares, root = env
    v = Vault(d)
    for share in shares[:3]:
        v.unseal(share)
    return v, v.authenticate(root), env
