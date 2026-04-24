from peachfuzz_ai.radar import projects, strategic_thesis, to_json, to_markdown, top_priorities
from peachfuzz_ai.roadmap import ranked, to_json as roadmap_json, to_markdown as roadmap_markdown


def test_radar_contains_agent_and_coverage_families():
    names = {p.name for p in projects()}
    assert "AFL++" in names
    assert "ToolFuzz" in names
    assert "OSS-Fuzz ecosystem" in names


def test_top_priorities_are_high_signal():
    top = top_priorities(3)
    assert len(top) == 3
    assert all(p.priority <= 1 for p in top)


def test_radar_outputs():
    assert "AI-agent-aware" in strategic_thesis()
    assert "AFL++" in to_markdown()
    assert "ToolFuzz" in to_json()


def test_roadmap_ranked_outputs():
    items = ranked()
    assert items[0].score >= items[-1].score
    assert "Agent guardrail" in roadmap_markdown()
    assert "Backend adapter" in roadmap_json()
