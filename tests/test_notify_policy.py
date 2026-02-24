import os
import sys
from pathlib import Path

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from utils.notify_policy import get_balance_change_mode, should_compare_and_save_balance_hash


def test_get_balance_change_mode_defaults_to_strict_when_unset(monkeypatch):
    monkeypatch.delenv("BALANCE_CHANGE_MODE", raising=False)
    assert get_balance_change_mode() == "strict"


def test_get_balance_change_mode_accepts_legacy_alias(monkeypatch):
    monkeypatch.setenv("BALANCE_CHANGE_MODE", "compat")
    assert get_balance_change_mode() == "legacy"


def test_get_balance_change_mode_accepts_strict_alias(monkeypatch):
    monkeypatch.setenv("BALANCE_CHANGE_MODE", "stable")
    assert get_balance_change_mode() == "strict"


def test_should_compare_and_save_balance_hash_strict_requires_clean_run():
    assert should_compare_and_save_balance_hash("strict", has_account_failure=False, has_partial_failure=False)
    assert not should_compare_and_save_balance_hash("strict", has_account_failure=True, has_partial_failure=False)
    assert not should_compare_and_save_balance_hash("strict", has_account_failure=False, has_partial_failure=True)


def test_should_compare_and_save_balance_hash_legacy_always_compares():
    assert should_compare_and_save_balance_hash("legacy", has_account_failure=False, has_partial_failure=False)
    assert should_compare_and_save_balance_hash("legacy", has_account_failure=True, has_partial_failure=True)
