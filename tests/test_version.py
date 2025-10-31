"""Test basic package functionality."""

import sentyr


def test_version() -> None:
    """Test that version is defined."""
    assert sentyr.__version__ == "0.1.0"


def test_package_metadata() -> None:
    """Test that package metadata is defined."""
    assert sentyr.__author__ is not None
    assert sentyr.__license__ == "MIT"

