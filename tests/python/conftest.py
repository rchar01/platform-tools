from collections.abc import Callable, Generator
from pathlib import Path

import pytest

from .harness import ManagedProcess, ProcessResult, ProcessTracker, copy_tree


@pytest.fixture
def process_tracker() -> Generator[ProcessTracker, None, None]:
    tracker = ProcessTracker()
    yield tracker
    tracker.close()


@pytest.fixture
def process_runner(process_tracker: ProcessTracker) -> Callable[..., ProcessResult]:
    return process_tracker.run


@pytest.fixture
def process_starter(process_tracker: ProcessTracker) -> Callable[..., ManagedProcess]:
    return process_tracker.start


@pytest.fixture
def tree_copier() -> Callable[[Path, Path], None]:
    return copy_tree
