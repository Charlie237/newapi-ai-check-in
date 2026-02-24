import sys
from datetime import datetime
from pathlib import Path

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from utils.summary_notify import build_summary_html, build_summary_message


def test_build_summary_message_keeps_unicode_names():
    failed_name = "AnyRouter \u56fd\u5185"
    highlight_name = "\u4e91\u7aef\u6d4b\u8bd5"

    content = build_summary_message(
        workflow="main/checkin",
        success_count=1,
        total_count=2,
        metrics={"accounts_success": "1/2"},
        reasons=["account_failure"],
        failed_items=[failed_name],
        highlight_items=[highlight_name],
        auth_rows=[
            {
                "account": highlight_name,
                "method": "user",
                "cache": "hit",
                "result": "ok",
                "detail": "-",
            },
            {
                "account": failed_name,
                "method": "linux.do",
                "cache": "miss",
                "result": "fail",
                "detail": "Linux.do sign-in error",
            },
        ],
        now=datetime(2026, 2, 18, 10, 18, 45),
    )

    assert "successful_auth:" in content
    assert "failed_auth:" in content
    assert "| Account | Auth Method | Cache | Result | Detail |" in content
    assert f"| {highlight_name} | user | hit | ok | - |" in content
    assert f"| {failed_name} | linux.do | miss | fail | Linux.do sign-in error |" in content


def test_build_summary_html_keeps_unicode_names_and_structure():
    failed_name = "AnyRouter \u56fd\u5185(linux.do: \u767b\u5f55\u5931\u8d25)"
    highlight_name = "\u4e91\u7aef\u6d4b\u8bd5(ok: linux.do)"

    html = build_summary_html(
        workflow="main/checkin",
        success_count=1,
        total_count=2,
        metrics={"accounts_success": "1/2", "auth_methods_success": "1/2"},
        reasons=["account_failure", "balance_changed"],
        failed_items=[failed_name],
        highlight_items=[highlight_name],
        auth_rows=[
            {
                "account": "Demo",
                "method": "user",
                "cache": "hit",
                "result": "ok",
                "detail": "-",
            },
            {
                "account": "Demo",
                "method": "linux.do",
                "cache": "miss",
                "result": "fail",
                "detail": "Linux.do sign-in error",
            },
        ],
        now=datetime(2026, 2, 18, 10, 18, 45),
    )

    assert "<!doctype html>" in html.lower()
    assert "Check-in Summary" in html
    assert "workflow:</strong> main/checkin" in html
    assert "PARTIAL" in html
    assert "Successful Auth" in html
    assert "Failed Auth" in html
    assert "Account</th>" in html
    assert "Auth Method</th>" in html
    assert '<col class="col-account" />' in html
    assert '<col class="col-method" />' in html
    assert ".auth-table col.col-account { width: 24%; }" in html
    assert "account_failure" in html
    assert "balance_changed" in html
    assert ">Demo</td>" in html
    assert ">user</td>" in html
    assert ">linux.do</td>" in html
    assert "Linux.do sign-in error" in html


def test_build_summary_message_includes_balance_items():
    failed_name = "AnyRouter \u56fd\u5185(linux.do: \u767b\u5f55\u5931\u8d25)"
    balance_name = "\u4e91\u7aef\u6d4b\u8bd5(user1: $12.3 (used:$1.2, bonus:$0))"

    content = build_summary_message(
        workflow="main/checkin",
        success_count=1,
        total_count=2,
        metrics={"accounts_success": "1/2"},
        reasons=["account_failure"],
        failed_items=[failed_name],
        balance_items=[balance_name],
        now=datetime(2026, 2, 18, 10, 18, 45),
    )

    assert "successful_auth:" in content
    assert "failed_auth:" in content
    assert failed_name in content
    assert balance_name in content


def test_build_summary_message_does_not_truncate_balances_and_failures():
    balances = [f"account{i}(user1: ${i} (used:$0, bonus:$0))" for i in range(1, 12)]
    failed_items = [f"account{i}(user{i}:HTTP 401 Unauthorized)" for i in range(1, 12)]
    partial_items = [f"account{i}(ok:user1 fail:user2:invalid password)" for i in range(1, 12)]

    content = build_summary_message(
        workflow="main/checkin",
        success_count=3,
        total_count=11,
        reasons=["account_failure", "partial_failure"],
        failed_items=failed_items,
        partial_items=partial_items,
        balance_items=balances,
        now=datetime(2026, 2, 18, 10, 18, 45),
    )

    assert "successful_auth:" in content
    assert "failed_auth:" in content
    assert "... (+" not in content
    assert balances[-1] in content
    assert failed_items[-1] in content
    assert partial_items[-1] in content
