from __future__ import annotations

from pathlib import Path


def test_skill_policy_requires_report_markdown_output() -> None:
    skill_path = (
        Path(__file__).resolve().parents[1]
        / "dump-analysis-skill"
        / "SKILL.md"
    )
    text = skill_path.read_text(encoding="utf-8")

    assert "`report_markdown` as the final answer body" in text
    assert "replace `report_markdown` with a free-form summary" in text
    assert "Response Policy (Strict)" in text
