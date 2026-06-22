from collections.abc import Callable
from typing import Any


class LocalStructuredTool:
    """Small LangChain-compatible fallback used when langchain is not installed."""

    def __init__(self, name: str, description: str, func: Callable[..., Any]) -> None:
        self.name = name
        self.description = description
        self.func = func

    def invoke(self, input: dict | Any) -> Any:
        if isinstance(input, dict):
            return self.func(**input)
        return self.func(input)


def make_structured_tool(name: str, description: str, func: Callable[..., Any]):
    try:
        from langchain_core.tools import StructuredTool
    except ImportError:
        return LocalStructuredTool(name=name, description=description, func=func)

    return StructuredTool.from_function(
        func=func,
        name=name,
        description=description,
    )
