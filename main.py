#!/usr/bin/env python3
"""
自动签到脚本
"""

import asyncio
import hashlib
import json
import os
import sys
from datetime import datetime
from dotenv import load_dotenv
from utils.config import AppConfig
from utils.notify import notify
from utils.balance_hash import load_balance_hash, save_balance_hash
from utils.summary_notify import build_summary_message
from checkin import CheckIn

load_dotenv(override=True)

BALANCE_HASH_FILE = "balance_hash.txt"


def generate_balance_hash(balances: dict) -> str:
    """生成余额数据的hash"""
    # 将包含 quota 和 used 的结构转换为 {account_name: [quota]} 格式用于 hash 计算
    simple_balances = {}
    if balances:
        for account_key, account_balances in balances.items():
            quota_list = []
            for _, balance_info in account_balances.items():
                quota_list.append(balance_info["quota"])
            simple_balances[account_key] = quota_list

    balance_json = json.dumps(simple_balances, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(balance_json.encode("utf-8")).hexdigest()[:16]


def _normalize_notify_format(value: str | None, default: str = "both") -> str:
    """Normalize notify format to one of: detail, summary, both."""
    if not value:
        return default
    normalized = str(value).strip().lower()
    if normalized in {"detail", "detailed"}:
        return "detail"
    if normalized in {"summary", "brief"}:
        return "summary"
    if normalized in {"both", "all", "full"}:
        return "both"
    return default


async def main():
    """运行签到流程

    Returns:
            退出码: 0 表示至少有一个账号成功, 1 表示全部失败
    """

    print("🚀 newapi.ai multi-account auto check-in script started (using Camoufox)")
    print(f'🕒 Execution time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')

    app_config = AppConfig.load_from_env()
    print(f"⚙️ Loaded {len(app_config.providers)} provider(s)")

    # 检查账号配置
    if not app_config.accounts:
        print("❌ Unable to load account configuration, program exits")
        return 1
    
    print(f"⚙️ Found {len(app_config.accounts)} account(s)")
    notify_format = _normalize_notify_format(os.getenv("CHECKIN_NOTIFY_FORMAT"), default="both")
    print(f"⚙️ notify_format={notify_format}")

    # 加载余额hash
    last_balance_hash = load_balance_hash(BALANCE_HASH_FILE)

    # 为每个账号执行签到
    success_count = 0  # 按认证方式统计
    total_count = 0  # 按认证方式统计
    account_success_count = 0  # 按账号统计
    current_balances = {}
    need_notify = False  # 是否需要发送通知
    has_account_failure = False
    has_partial_failure = False
    failed_accounts: list[str] = []
    partial_accounts: list[str] = []
    highlight_accounts: list[str] = []
    first_run = False
    balance_changed = False

    for i, account_config in enumerate(app_config.accounts):
        account_key = f"account_{i + 1}"
        account_name = account_config.get_display_name(i)

        try:
            provider_config = app_config.get_provider(account_config.provider)
            if not provider_config:
                print(f"❌ {account_name}: Provider '{account_config.provider}' configuration not found")
                need_notify = True
                has_account_failure = True
                failed_accounts.append(
                    f"{account_name}(provider missing: {account_config.provider})"
                )
                continue

            print(f"🌀 Processing {account_name} using provider '{account_config.provider}'")
            checkin = CheckIn(account_name, account_config, provider_config, global_proxy=app_config.global_proxy)
            results = await checkin.execute()

            total_count += len(results)
            if not results:
                need_notify = True
                has_account_failure = True
                failed_accounts.append(f"{account_name}(no valid auth method)")
                continue

            # 处理多个认证方式的结果
            account_success = False
            successful_methods: list[str] = []
            failed_methods: list[str] = []
            fail_notes: list[str] = []
            this_account_balances = {}

            for auth_method, success, user_info in results:
                if success and user_info and user_info.get("success"):
                    account_success = True
                    success_count += 1
                    successful_methods.append(auth_method)

                    # 记录余额信息
                    current_quota = user_info["quota"]
                    current_used = user_info["used_quota"]
                    current_bonus = user_info["bonus_quota"]
                    this_account_balances[auth_method] = {
                        "quota": current_quota,
                        "used": current_used,
                        "bonus": current_bonus,
                    }
                else:
                    failed_methods.append(auth_method)
                    error_msg = user_info.get("error", "Unknown error") if user_info else "Unknown error"
                    fail_notes.append(f"{auth_method}:{str(error_msg)[:60]}")

            if account_success:
                account_success_count += 1
                current_balances[account_key] = this_account_balances
                highlight = f"{account_name}(ok: {','.join(successful_methods)})"
                highlight_accounts.append(highlight)

            # 如果所有认证方式都失败，需要通知
            if not account_success and results:
                need_notify = True
                has_account_failure = True
                fail_note = fail_notes[0] if fail_notes else "all methods failed"
                failed_accounts.append(f"{account_name}({fail_note})")
                print(f"🔔 {account_name} all authentication methods failed, will send notification")

            # 如果有失败的认证方式，也通知
            if failed_methods and successful_methods:
                need_notify = True
                has_partial_failure = True
                partial_accounts.append(
                    f"{account_name}(ok:{','.join(successful_methods)} fail:{','.join(failed_methods)})"
                )
                print(f"🔔 {account_name} has some failed authentication methods, will send notification")

        except Exception as e:
            print(f"❌ {account_name} processing exception: {e}")
            need_notify = True  # 异常也需要通知
            has_account_failure = True
            failed_accounts.append(f"{account_name}(exception: {str(e)[:80]})")

    # 检查余额变化
    current_balance_hash = generate_balance_hash(current_balances) if current_balances else None
    print(f"\n\nℹ️ Current balance hash: {current_balance_hash}, Last balance hash: {last_balance_hash}")
    if current_balance_hash:
        if last_balance_hash is None:
            # 首次运行
            need_notify = True
            first_run = True
            print("🔔 First run detected, will send notification with current balances")
        elif current_balance_hash != last_balance_hash:
            # 余额有变化
            need_notify = True
            balance_changed = True
            print("🔔 Balance changes detected, will send notification")
        else:
            print("ℹ️ No balance changes detected")

    # 保存当前余额hash
    if current_balance_hash:
        save_balance_hash(BALANCE_HASH_FILE, current_balance_hash)

    if need_notify:
        reasons: list[str] = []
        if has_account_failure:
            reasons.append("account_failure")
        if has_partial_failure:
            reasons.append("partial_failure")
        if first_run:
            reasons.append("first_run")
        if balance_changed:
            reasons.append("balance_changed")
        if not reasons:
            reasons.append("manual")

        metrics = {
            "accounts_success": f"{account_success_count}/{len(app_config.accounts)}",
            "auth_methods_success": f"{success_count}/{total_count}",
        }
        summary_content = build_summary_message(
            workflow="main/checkin",
            success_count=account_success_count,
            total_count=len(app_config.accounts),
            metrics=metrics,
            reasons=reasons,
            failed_items=failed_accounts,
            partial_items=partial_accounts,
            highlight_items=highlight_accounts,
        )
        notify_title = "Check-in Alert" if (has_account_failure or has_partial_failure) else "Check-in Summary"

        detail_lines: list[str] = [
            f"time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"accounts_success: {account_success_count}/{len(app_config.accounts)}",
            f"auth_methods_success: {success_count}/{total_count}",
        ]
        if failed_accounts:
            detail_lines.append("failed_accounts: " + "; ".join(failed_accounts))
        if partial_accounts:
            detail_lines.append("partial_accounts: " + "; ".join(partial_accounts))
        if highlight_accounts:
            detail_lines.append("highlights: " + "; ".join(highlight_accounts))

        sections: list[str] = []
        if notify_format in {"detail", "both"}:
            sections.append("\n".join(detail_lines))
        if notify_format in {"summary", "both"}:
            sections.append(summary_content)
        notify_content = "\n\n".join(sections) if sections else summary_content

        print(notify_content)
        notify.push_message(notify_title, notify_content, msg_type="text")
        print("🔔 Notification sent due to failures or balance changes")
    else:
        print("ℹ️ All accounts successful and no balance changes detected, notification skipped")

    # 设置退出码
    sys.exit(0 if success_count > 0 else 1)


def run_main():
    """运行主函数的包装函数"""
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n⚠️ Program interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error occurred during program execution: {e}")
        sys.exit(1)


if __name__ == "__main__":
    run_main()
