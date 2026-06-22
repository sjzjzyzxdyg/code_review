import json
import re
from typing import Literal

from pydantic import BaseModel, Field, ValidationError


class ValidatedReviewResult(BaseModel):
    is_valid: bool = True
    risk_level: Literal["low", "medium", "high", "critical"] = "medium"
    issue_type: str = "static-analysis"
    description: str = "Static analysis finding"
    reason: str = "The analyzer reported a candidate issue."
    fix_suggestion: str = "Review and fix the reported code path."
    confidence: float = Field(default=0.5, ge=0, le=1)


class ResultValidationAgent:
    """Normalizes and validates LLM review results."""

    JSON_BLOCK_PATTERN = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)

    def validate(
        self,
        review_result,
        call_chain: list[str] | None = None,
    ) -> ValidatedReviewResult:
        review_result = self._coerce_to_dict(review_result)
        try:
            validated = ValidatedReviewResult.model_validate(review_result)
        except ValidationError:
            repaired = {
                "is_valid": bool(review_result.get("is_valid", True)),
                "risk_level": self._normalize_risk_level(review_result.get("risk_level")),
                "issue_type": str(review_result.get("issue_type") or "static-analysis"),
                "description": str(review_result.get("description") or "Static analysis finding"),
                "reason": str(review_result.get("reason") or "The analyzer reported a candidate issue."),
                "fix_suggestion": str(
                    review_result.get("fix_suggestion")
                    or "Review and fix the reported code path."
                ),
                "confidence": self._normalize_confidence(review_result.get("confidence")),
            }
            validated = ValidatedReviewResult.model_validate(repaired)

        return self._filter_false_positive(validated, call_chain=call_chain or [])

    def _coerce_to_dict(self, value) -> dict:
        if isinstance(value, dict):
            return value
        if isinstance(value, BaseModel):
            return value.model_dump()
        if not isinstance(value, str):
            return {}

        text = value.strip()
        block = self.JSON_BLOCK_PATTERN.search(text)
        if block:
            text = block.group(1)
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            return self._extract_markdown_fields(value)
        return parsed if isinstance(parsed, dict) else {}

    def _extract_markdown_fields(self, text: str) -> dict:
        fields = {}
        aliases = {
            "risk": "risk_level",
            "risk_level": "risk_level",
            "issue_type": "issue_type",
            "description": "description",
            "reason": "reason",
            "fix": "fix_suggestion",
            "fix_suggestion": "fix_suggestion",
            "confidence": "confidence",
            "is_valid": "is_valid",
        }
        for raw_line in text.splitlines():
            if ":" not in raw_line:
                continue
            key, raw_value = raw_line.split(":", 1)
            normalized_key = key.strip().lower().replace(" ", "_").strip("-*")
            target = aliases.get(normalized_key)
            if target:
                fields[target] = raw_value.strip()
        return fields

    def _filter_false_positive(
        self,
        result: ValidatedReviewResult,
        call_chain: list[str] | None = None,
    ) -> ValidatedReviewResult:
        if result.confidence < 0.2:
            return result.model_copy(update={"is_valid": False})

        benign_markers = ("false positive", "not exploitable", "intentional")
        searchable = f"{result.reason} {result.description}".lower()
        if any(marker in searchable for marker in benign_markers):
            return result.model_copy(update={"is_valid": False})

        if call_chain:
            all_good = all(fn.lower().startswith("good") for fn in call_chain)
            if all_good:
                suppressed_confidence = round(min(result.confidence * 0.35, 0.25), 2)
                return result.model_copy(
                    update={"is_valid": False, "confidence": suppressed_confidence}
                )

        return result

    def _normalize_risk_level(self, value) -> str:
        normalized = str(value or "medium").lower()
        if normalized in {"low", "medium", "high", "critical"}:
            return normalized
        return "medium"

    def _normalize_confidence(self, value) -> float:
        try:
            confidence = float(value)
        except (TypeError, ValueError):
            return 0.5
        return min(max(confidence, 0), 1)
