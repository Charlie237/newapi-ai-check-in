from datetime import datetime
from pathlib import Path
import sys


project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from utils.summary_notify import build_summary_message


def test_build_summary_message_keeps_unicode_names():
    failed_name = 'AnyRouter \u56fd\u5185(linux.do: \u767b\u5f55\u5931\u8d25)'
    highlight_name = '\u4e91\u7aef\u6d4b\u8bd5(ok: linux.do)'

    content = build_summary_message(
        workflow='main/checkin',
        success_count=1,
        total_count=2,
        metrics={'accounts_success': '1/2'},
        reasons=['account_failure'],
        failed_items=[failed_name],
        highlight_items=[highlight_name],
        now=datetime(2026, 2, 18, 10, 18, 45),
    )

    assert failed_name in content
    assert highlight_name in content
