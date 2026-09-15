from pathlib import Path

from app.agents.llm_review_agent import LLMReviewAgent


def test_validate_path_allows_paths_inside_root(tmp_path: Path) -> None:
    agent = LLMReviewAgent()
    target = tmp_path / "src" / "main.cpp"
    target.parent.mkdir(parents=True)
    target.write_text("int main() { return 0; }")

    resolved = agent._validate_path(str(target), tmp_path.resolve())

    assert resolved == target.resolve()


def test_validate_path_blocks_paths_outside_root(tmp_path: Path) -> None:
    agent = LLMReviewAgent()
    outside = tmp_path.parent / "outside.txt"

    resolved = agent._validate_path(str(outside), tmp_path.resolve())

    assert resolved is None


def test_validate_path_blocks_traversal_via_dotdot(tmp_path: Path) -> None:
    agent = LLMReviewAgent()
    root = tmp_path / "project"
    root.mkdir()
    traversal = f"{root}/../secret.txt"

    resolved = agent._validate_path(traversal, root.resolve())

    assert resolved is None


def test_validate_path_returns_none_without_root() -> None:
    agent = LLMReviewAgent()

    assert agent._validate_path("/anything", None) is None


def test_execute_tool_blocks_disallowed_file_path(tmp_path: Path) -> None:
    agent = LLMReviewAgent()
    root = tmp_path / "project"
    root.mkdir()
    outside = tmp_path / "secret.txt"
    outside.write_text("top secret")

    result = agent._execute_tool(
        "read_code_snippet",
        {"file_path": str(outside), "start_line": 1, "end_line": 1},
        root.resolve(),
    )

    assert "error" in result
    assert "top secret" not in str(result)
