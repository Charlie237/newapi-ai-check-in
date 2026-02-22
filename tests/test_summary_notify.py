from datetime import datetime
from pathlib import Path
import sys


project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from utils.summary_notify import build_summary_message


def test_build_summary_message_keeps_unicode_names():
    failed_name = 'AnyRouter \u56fd\u5185(linux.do: \u767b\u5f55\u5931\u8d25)'
    balance_name = '\u4e91\u7aef\u6d4b\u8bd5(user1: $12.3 (used:$1.2, bonus:$0))'

    content = build_summary_message(
        workflow='main/checkin',
        success_count=1,
        total_count=2,
        metrics={'accounts_success': '1/2'},
        reasons=['account_failure'],
        failed_items=[failed_name],
        balance_items=[balance_name],
        now=datetime(2026, 2, 18, 10, 18, 45),
    )

    assert failed_name in content
    assert balance_name in content
    assert 'balances:' in content


def test_build_summary_message_does_not_truncate_balances_and_failures():
    balances = [f'account{i}(user1: ${i} (used:$0, bonus:$0))' for i in range(1, 12)]
    failed_items = [f'account{i}(user{i}:HTTP 401 Unauthorized)' for i in range(1, 12)]
    partial_items = [f'account{i}(ok:user1 fail:user2:invalid password)' for i in range(1, 12)]

    content = build_summary_message(
        workflow='main/checkin',
        success_count=3,
        total_count=11,
        reasons=['account_failure', 'partial_failure'],
        failed_items=failed_items,
        partial_items=partial_items,
        balance_items=balances,
        now=datetime(2026, 2, 18, 10, 18, 45),
    )

    assert '... (+' not in content
    assert balances[-1] in content
    assert failed_items[-1] in content
    assert partial_items[-1] in content
