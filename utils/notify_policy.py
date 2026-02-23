#!/usr/bin/env python3
"""
Notification policy helpers.
"""

from __future__ import annotations

import os
from typing import Literal

BalanceChangeMode = Literal["strict", "legacy"]


def get_balance_change_mode(
    env_name: str = "BALANCE_CHANGE_MODE",
    default: BalanceChangeMode = "strict",
) -> BalanceChangeMode:
    raw = str(os.getenv(env_name, "")).strip().lower()
    if raw in {"legacy", "compat", "loose"}:
        return "legacy"
    if raw in {"strict", "stable"}:
        return "strict"
    return default


def should_compare_and_save_balance_hash(
    mode: BalanceChangeMode,
    has_account_failure: bool,
    has_partial_failure: bool = False,
) -> bool:
    if mode == "legacy":
        return True
    return not (has_account_failure or has_partial_failure)
