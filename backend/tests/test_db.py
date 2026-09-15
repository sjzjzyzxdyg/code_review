from pathlib import Path

from app.core.db import Database


def test_upsert_and_get_round_trip(tmp_path: Path) -> None:
    db = Database(tmp_path / "test.db")

    db.upsert("projects", "p1", None, "2024-01-01T00:00:00", {"id": "p1", "name": "demo"})

    assert db.get("projects", "p1") == {"id": "p1", "name": "demo"}
    assert db.get("projects", "missing") is None


def test_upsert_overwrites_existing_row(tmp_path: Path) -> None:
    db = Database(tmp_path / "test.db")
    db.upsert("projects", "p1", None, "2024-01-01T00:00:00", {"id": "p1", "name": "v1"})

    db.upsert("projects", "p1", None, "2024-01-01T00:00:00", {"id": "p1", "name": "v2"})

    assert db.get("projects", "p1") == {"id": "p1", "name": "v2"}
    assert len(db.list("projects")) == 1


def test_list_filters_by_parent_id(tmp_path: Path) -> None:
    db = Database(tmp_path / "test.db")
    db.upsert("issues", "i1", "task-a", "t1", {"id": "i1", "task_id": "task-a"})
    db.upsert("issues", "i2", "task-a", "t2", {"id": "i2", "task_id": "task-a"})
    db.upsert("issues", "i3", "task-b", "t3", {"id": "i3", "task_id": "task-b"})

    assert {row["id"] for row in db.list("issues", parent_id="task-a")} == {"i1", "i2"}
    assert {row["id"] for row in db.list("issues")} == {"i1", "i2", "i3"}


def test_replace_children_is_atomic_delete_then_insert(tmp_path: Path) -> None:
    db = Database(tmp_path / "test.db")
    db.upsert("issues", "old-1", "task-a", "t0", {"id": "old-1"})

    db.replace_children(
        "issues", "task-a",
        [("new-1", "t1", {"id": "new-1"}), ("new-2", "t2", {"id": "new-2"})],
    )

    ids = {row["id"] for row in db.list("issues", parent_id="task-a")}
    assert ids == {"new-1", "new-2"}


def test_data_survives_reopening_the_same_file(tmp_path: Path) -> None:
    """Simulates a process restart: a fresh Database instance over the same
    file must see everything a previous instance wrote."""
    path = tmp_path / "test.db"
    first = Database(path)
    first.upsert("projects", "p1", None, "2024-01-01T00:00:00", {"id": "p1", "name": "demo"})

    second = Database(path)

    assert second.get("projects", "p1") == {"id": "p1", "name": "demo"}
