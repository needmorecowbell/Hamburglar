"""Tests for the hamburglar.rules module.

This module tests the bundled YARA rules package to ensure:
- The rules directory is accessible
- All YARA rule files are present
- The helper functions work correctly
"""

from __future__ import annotations

from pathlib import Path

import pytest

from hamburglar.rules import RULES_DIR, get_rules_path, list_rules


class TestRulesPath:
    """Tests for get_rules_path function."""

    def test_get_rules_path_returns_path(self) -> None:
        """get_rules_path should return a Path object."""
        rules_path = get_rules_path()
        assert isinstance(rules_path, Path)

    def test_get_rules_path_exists(self) -> None:
        """get_rules_path should return an existing directory."""
        rules_path = get_rules_path()
        assert rules_path.exists()
        assert rules_path.is_dir()

    def test_rules_dir_constant(self) -> None:
        """RULES_DIR constant should match get_rules_path."""
        assert get_rules_path() == RULES_DIR


class TestListRules:
    """Tests for list_rules function."""

    def test_list_rules_returns_list(self) -> None:
        """list_rules should return a list."""
        rules = list_rules()
        assert isinstance(rules, list)

    def test_list_rules_contains_yar_files(self) -> None:
        """list_rules should only contain .yar files."""
        rules = list_rules()
        for rule in rules:
            assert rule.suffix == ".yar"

    def test_list_rules_count(self) -> None:
        """list_rules should return all 19 YARA rule files."""
        rules = list_rules()
        assert len(rules) == 19

    def test_list_rules_files_exist(self) -> None:
        """All files returned by list_rules should exist."""
        rules = list_rules()
        for rule in rules:
            assert rule.exists()
            assert rule.is_file()


class TestExpectedRules:
    """Tests to verify all expected YARA rule files are present."""

    EXPECTED_RULES = [
        "apple.yar",
        "audio.yar",
        "compressed.yar",
        "crypto.yar",
        "executables.yar",
        "gif.yar",
        "gps.yar",
        "jpeg.yar",
        "mem_dumps.yar",
        "office.yar",
        "pdf.yar",
        "png.yar",
        "skype.yar",
        "sqlite.yar",
        "vcard.yar",
        "vector.yar",
        "video.yar",
        "vmware.yar",
        "win_reg.yar",
    ]

    def test_all_expected_rules_present(self) -> None:
        """All expected YARA rule files should be present."""
        rules = list_rules()
        rule_names = {rule.name for rule in rules}

        for expected_rule in self.EXPECTED_RULES:
            assert expected_rule in rule_names, f"Missing rule: {expected_rule}"

    @pytest.mark.parametrize("rule_name", EXPECTED_RULES)
    def test_individual_rule_exists(self, rule_name: str) -> None:
        """Each expected rule should exist in the rules directory."""
        rules_path = get_rules_path()
        rule_path = rules_path / rule_name
        assert rule_path.exists(), f"Rule file not found: {rule_name}"


class TestRulesContent:
    """Tests to verify YARA rule files have valid content."""

    def test_rules_are_not_empty(self) -> None:
        """All YARA rule files should have content."""
        rules = list_rules()
        for rule in rules:
            content = rule.read_text()
            assert len(content) > 0, f"Rule file is empty: {rule.name}"

    def test_rules_contain_yara_syntax(self) -> None:
        """YARA rule files should contain basic YARA syntax (rule keyword)."""
        rules = list_rules()
        for rule in rules:
            content = rule.read_text()
            # Basic check that the file contains YARA rule syntax
            assert "rule" in content.lower(), f"Rule file missing 'rule' keyword: {rule.name}"
