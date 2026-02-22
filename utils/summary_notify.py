#!/usr/bin/env python3
"""
统一的通知摘要格式工具。
"""

from __future__ import annotations

from datetime import datetime


def _build_status(success_count: int, total_count: int) -> str:
    if total_count <= 0:
        return "unknown"
    if success_count == total_count:
        return "success"
    if success_count > 0:
        return "partial"
    return "failed"


def _format_items(items: list[str], max_items: int | None = 8) -> str:
    if not items:
        return "-"

    trimmed = [item for item in items if item]
    if not trimmed:
        return "-"

    if max_items is None:
        return "; ".join(trimmed)

    shown = trimmed[:max_items]
    extra = len(trimmed) - len(shown)
    content = "; ".join(shown)
    if extra > 0:
        content += f"; ... (+{extra})"
    return content


def build_summary_message(
    workflow: str,
    success_count: int,
    total_count: int,
    metrics: dict[str, str] | None = None,
    reasons: list[str] | None = None,
    failed_items: list[str] | None = None,
    partial_items: list[str] | None = None,
    balance_items: list[str] | None = None,
    highlight_items: list[str] | None = None,
    now: datetime | None = None,
) -> str:
    """构建统一摘要通知正文。"""

    now_time = now or datetime.now()
    status = _build_status(success_count, total_count)
    failed_count = max(total_count - success_count, 0)

    lines = [
        "[Check-in Summary]",
        f"time: {now_time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"workflow: {workflow}",
        f"status: {status}",
        f"success: {success_count}/{total_count}",
        f"failed: {failed_count}/{total_count}",
    ]

    if metrics:
        for key, value in metrics.items():
            lines.append(f"{key}: {value}")

    if reasons:
        lines.append(f"trigger: {_format_items(reasons, max_items=6)}")

    if failed_items:
        lines.append(f"failed_accounts: {_format_items(failed_items, max_items=None)}")

    if partial_items:
        lines.append(f"partial_accounts: {_format_items(partial_items, max_items=None)}")

    if balance_items:
        lines.append(f"balances: {_format_items(balance_items, max_items=None)}")

    if highlight_items:
        lines.append(f"highlights: {_format_items(highlight_items, max_items=None)}")

    return "\n".join(lines)
