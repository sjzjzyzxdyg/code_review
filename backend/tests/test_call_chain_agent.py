from pathlib import Path

from app.agents.call_chain_agent import CallChainRetrievalAgent

_SOURCE = """
void inner() {
    int x = 1;
}

void outer() {
    inner();
}

int main() {
    outer();
    return 0;
}
"""


def test_retrieve_graph_follows_call_chain(tmp_path: Path) -> None:
    source_file = tmp_path / "main.cpp"
    source_file.write_text(_SOURCE)
    agent = CallChainRetrievalAgent()

    graph = agent.retrieve_graph({"file_path": str(source_file), "line": 7})

    assert graph["entry"] == "outer"
    assert graph["chain"] == ["outer", "inner"]
