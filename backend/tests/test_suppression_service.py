from pathlib import Path

from app.core.db import Database
from app.services.suppression_service import SuppressionService


def test_unsuppressed_finding_is_not_suppressed(tmp_path: Path) -> None:
    service = SuppressionService(db=Database(tmp_path / "test.db"))

    assert not service.is_suppressed("proj-1", "src/main.cpp", "nullPointer", 42)


def test_suppress_then_is_suppressed(tmp_path: Path) -> None:
    service = SuppressionService(db=Database(tmp_path / "test.db"))

    service.suppress("proj-1", "src/main.cpp", "nullPointer", 42)

    assert service.is_suppressed("proj-1", "src/main.cpp", "nullPointer", 42)


def test_suppression_is_specific_to_file_rule_and_line(tmp_path: Path) -> None:
    service = SuppressionService(db=Database(tmp_path / "test.db"))
    service.suppress("proj-1", "src/main.cpp", "nullPointer", 42)

    assert not service.is_suppressed("proj-1", "src/other.cpp", "nullPointer", 42)
    assert not service.is_suppressed("proj-1", "src/main.cpp", "otherRule", 42)
    assert not service.is_suppressed("proj-1", "src/main.cpp", "nullPointer", 43)


def test_suppression_is_specific_to_project(tmp_path: Path) -> None:
    service = SuppressionService(db=Database(tmp_path / "test.db"))
    service.suppress("proj-1", "src/main.cpp", "nullPointer", 42)

    assert not service.is_suppressed("proj-2", "src/main.cpp", "nullPointer", 42)


def test_list_suppressions_returns_only_this_project(tmp_path: Path) -> None:
    service = SuppressionService(db=Database(tmp_path / "test.db"))
    service.suppress("proj-1", "a.cpp", "ruleA", 1)
    service.suppress("proj-1", "b.cpp", "ruleB", 2)
    service.suppress("proj-2", "c.cpp", "ruleC", 3)

    entries = service.list_suppressions("proj-1")

    assert {e["file_path"] for e in entries} == {"a.cpp", "b.cpp"}


def test_suppressions_survive_service_restart(tmp_path: Path) -> None:
    db_path = tmp_path / "test.db"
    original = SuppressionService(db=Database(db_path))
    original.suppress("proj-1", "src/main.cpp", "nullPointer", 42)

    restarted = SuppressionService(db=Database(db_path))

    assert restarted.is_suppressed("proj-1", "src/main.cpp", "nullPointer", 42)
