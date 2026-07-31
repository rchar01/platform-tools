from collections.abc import Callable
from pathlib import Path

import pytest

from .harness import ProcessResult, copy_tree, run_process


@pytest.fixture
def process_runner() -> Callable[..., ProcessResult]:
    return run_process


@pytest.fixture
def tree_copier() -> Callable[[Path, Path], None]:
    return copy_tree
