import sys
from datetime import datetime
from pathlib import Path

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from utils.summary_notify import build_summary_html, build_summary_message


def test_build_summary_message_keeps_unicode_names():
    failed_name = 'AnyRouter \u56fd\u5185'
    highlight_name = '\u4e91\u7aef\u6d4b\u8bd5'

    content = build_summary_message(
        workflow='main/checkin',
        success_count=1,
        total_count=2,
        metrics={'accounts_success': '1/2'},
        reasons=['account_failure'],
        failed_items=[failed_name],
        highlight_items=[highlight_name],
        auth_rows=[
            {
                'account': highlight_name,
                'method': 'user',
                'cache': 'hit',
                'result': 'ok',
                'detail': '-',
            },
            {
                'account': failed_name,
                'method': 'linux.do',
                'cache': 'miss',
                'result': 'fail',
                'detail': 'Linux.do sign-in error',
            }
        ],
        now=datetime(2026, 2, 18, 10, 18, 45),
    )

    assert 'auth_success:' in content
    assert 'auth_failed:' in content
    assert f'- {highlight_name} | user | cache=hit | result=ok | -' in content
    assert f'- {failed_name} | linux.do | cache=miss | result=fail | Linux.do sign-in error' in content


def test_build_summary_html_keeps_unicode_names_and_structure():
    failed_name = 'AnyRouter \u56fd\u5185(linux.do: \u767b\u5f55\u5931\u8d25)'
    highlight_name = '\u4e91\u7aef\u6d4b\u8bd5(ok: linux.do)'

    html = build_summary_html(
        workflow='main/checkin',
        success_count=1,
        total_count=2,
        metrics={'accounts_success': '1/2', 'auth_methods_success': '1/2'},
        reasons=['account_failure', 'balance_changed'],
        failed_items=[failed_name],
        highlight_items=[highlight_name],
        auth_rows=[
            {
                'account': 'Demo',
                'method': 'user',
                'cache': 'hit',
                'result': 'ok',
                'detail': '-',
            },
            {
                'account': 'Demo',
                'method': 'linux.do',
                'cache': 'miss',
                'result': 'fail',
                'detail': 'Linux.do sign-in error',
            }
        ],
        now=datetime(2026, 2, 18, 10, 18, 45),
    )

    assert '<!doctype html>' in html.lower()
    assert 'Check-in Summary' in html
    assert 'workflow:</strong> main/checkin' in html
    assert 'PARTIAL' in html
    assert 'Successful Auth' in html
    assert 'Failed Auth' in html
    assert '<th>Account</th>' in html
    assert '<th>Auth Method</th>' in html
    assert '<col class="col-account" />' in html
    assert '<col class="col-method" />' in html
    assert '.auth-table col.col-account { width: 24%; }' in html
    assert 'account_failure' in html
    assert 'balance_changed' in html
    assert '<td>Demo</td>' in html
    assert '<td>user</td>' in html
    assert '<td>linux.do</td>' in html
    assert 'Linux.do sign-in error' in html
