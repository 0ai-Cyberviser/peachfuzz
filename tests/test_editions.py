import pytest

from peachfuzz_ai.editions import get_edition, edition_matrix_markdown


def test_edition_profiles():
    peach = get_edition("peachfuzz")
    cactus = get_edition("cactusfuzz")
    assert peach.requires_authorization is False
    assert cactus.requires_authorization is True
    assert "network scanning" in peach.blocked_by_default
    assert "unauthorized network scanning" in cactus.blocked_by_default


def test_unknown_edition():
    with pytest.raises(ValueError):
        get_edition("unknown")


def test_matrix_mentions_both():
    matrix = edition_matrix_markdown()
    assert "PeachFuzz" in matrix
    assert "CactusFuzz" in matrix
