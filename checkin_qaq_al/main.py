#!/usr/bin/env python3
"""
qaq.al auto check-in entrypoint.

Authentication strategy per account:
1) LinuxDo login + cached storage-state fallback
2) sid fallback (if provided)
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv

from checkin import CheckIn, LinuxDoCredential

sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.balance_hash import load_balance_hash, save_balance_hash
from utils.notify import notify

load_dotenv(override=True)

CHECKIN_HASH_FILE = "balance_hash_qaq_al.txt"


@dataclass
class AccountConfig:
    name: str
    sid: str
    credential: LinuxDoCredential | None


def _strip_code_fence(text: str) -> str:
    text = text.strip()
    if not text.startswith("```"):
        return text
    lines = text.splitlines()
    if len(lines) >= 2 and lines[0].startswith("```") and lines[-1].strip() == "```":
        return "\n".join(lines[1:-1]).strip()
    return text


def _parse_json_tolerant(text: str):
    candidate = text.strip()
    try:
        return json.loads(candidate)
    except json.JSONDecodeError as err:
        decoder = json.JSONDecoder()
        parsed, end = decoder.raw_decode(candidate)
        trailing = candidate[end:].strip()
        if trailing and not all(ch in ",;" for ch in trailing):
            raise err
        return parsed


def _to_bool(value, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        v = value.strip().lower()
        if v in {"1", "true", "yes", "on"}:
            return True
        if v in {"0", "false", "no", "off"}:
            return False
    return default


def _parse_linuxdo_credential(value) -> LinuxDoCredential | None:
    if not isinstance(value, dict):
        return None
    username = str(value.get("username", "")).strip()
    password = str(value.get("password", "")).strip()
    if username and password:
        return LinuxDoCredential(username=username, password=password)
    return None


def _load_global_linuxdo_accounts() -> list[LinuxDoCredential]:
    raw = os.getenv("ACCOUNTS_LINUX_DO", "").strip().lstrip("\ufeff")
    if not raw:
        return []

    try:
        parsed = _parse_json_tolerant(_strip_code_fence(raw))
    except Exception as exc:
        print(f"❌ Failed to parse ACCOUNTS_LINUX_DO: {exc}")
        return []

    if not isinstance(parsed, list):
        print("❌ ACCOUNTS_LINUX_DO must be a JSON array")
        return []

    items: list[LinuxDoCredential] = []
    for item in parsed:
        cred = _parse_linuxdo_credential(item)
        if cred:
            items.append(cred)
    return items


def _pick_credential(item: dict, global_accounts: list[LinuxDoCredential], index: int) -> LinuxDoCredential | None:
    for key in ("linux.do", "linuxdo"):
        if key in item:
            value = item[key]
            if value is True:
                if not global_accounts:
                    return None
                if index < len(global_accounts):
                    return global_accounts[index]
                return global_accounts[0]
            if isinstance(value, dict):
                return _parse_linuxdo_credential(value)
            if isinstance(value, list):
                for row in value:
                    cred = _parse_linuxdo_credential(row)
                    if cred:
                        return cred
            return None

    direct = _parse_linuxdo_credential(item)
    if direct:
        return direct
    return None


def load_accounts() -> list[AccountConfig] | None:
    """Load account list from ACCOUNTS_QAQ_AL."""
    raw = os.getenv("ACCOUNTS_QAQ_AL", "").strip()
    if not raw:
        print("❌ ACCOUNTS_QAQ_AL is empty")
        return None

    global_linuxdo = _load_global_linuxdo_accounts()

    try:
        normalized = _strip_code_fence(raw.lstrip("\ufeff"))
        if normalized.startswith("[") or normalized.startswith("{"):
            parsed = _parse_json_tolerant(normalized)
            if isinstance(parsed, dict):
                if "ACCOUNTS_QAQ_AL" not in parsed:
                    print("❌ ACCOUNTS_QAQ_AL is a JSON object but key ACCOUNTS_QAQ_AL is missing")
                    return None
                parsed = parsed["ACCOUNTS_QAQ_AL"]
            if not isinstance(parsed, list):
                print("❌ ACCOUNTS_QAQ_AL must be a JSON array")
                return None
            source_items = parsed
        else:
            # Backward compatibility: comma-separated sid string.
            source_items = [s.strip() for s in normalized.split(",") if s.strip()]
    except Exception as exc:
        print(f"❌ Failed to parse ACCOUNTS_QAQ_AL: {exc}")
        return None

    accounts: list[AccountConfig] = []
    for idx, item in enumerate(source_items):
        name = f"account_{idx + 1}"
        sid = ""
        credential: LinuxDoCredential | None = None

        if isinstance(item, str):
            sid = item.strip().strip('"').strip("'")
        elif isinstance(item, dict):
            name = str(item.get("name") or name)
            raw_sid = item.get("sid")
            if raw_sid is None:
                raw_sid = item.get("session")
            if raw_sid is None:
                cookies = item.get("cookies")
                if isinstance(cookies, dict):
                    raw_sid = cookies.get("sid")
            sid = str(raw_sid or "").strip().strip('"').strip("'")

            credential = _pick_credential(item, global_linuxdo, idx)
        else:
            continue

        if not sid and credential is None and global_linuxdo:
            credential = global_linuxdo[idx] if idx < len(global_linuxdo) else global_linuxdo[0]

        if not sid and credential is None:
            print(f"⚠️ Skip {name}: missing sid and linuxdo credential")
            continue

        accounts.append(AccountConfig(name=name, sid=sid, credential=credential))

    if not accounts:
        print("❌ No valid qaq.al account configuration")
        return None

    print(f"✅ Loaded {len(accounts)} qaq.al account(s)")
    return accounts


def generate_checkin_hash(results: dict) -> str:
    if not results:
        return ""
    rewards = {}
    for key, info in results.items():
        if info:
            rewards[key] = info.get("reward_final", "0")
    data = json.dumps(rewards, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(data.encode()).hexdigest()[:16]


async def main():
    print("🚀 qaq.al auto check-in started")
    print(f"🕒 run at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    accounts = load_accounts()
    if not accounts:
        print("❌ Failed to load account config, exit")
        return 1

    print(f"⚙️ total accounts: {len(accounts)}")

    last_hash = load_balance_hash(CHECKIN_HASH_FILE)
    if last_hash:
        print(f"ℹ️ last check-in hash: {last_hash}")
    else:
        print("ℹ️ first run, no previous hash")

    global_proxy = None
    proxy_str = os.getenv("PROXY")
    if proxy_str:
        try:
            global_proxy = json.loads(proxy_str)
            print("⚙️ proxy loaded as dict")
        except json.JSONDecodeError:
            global_proxy = {"server": proxy_str}
            print(f"⚙️ proxy loaded as url: {proxy_str}")

    tier = int(os.getenv("QAQ_AL_TIER", "4"))
    debug = _to_bool(os.getenv("DEBUG", "false"), default=False)
    print(f"⚙️ tier={tier}, debug={debug}")

    success_count = 0
    total_count = len(accounts)
    notification_content: list[str] = []
    current_info: dict = {}

    for account in accounts:
        if notification_content:
            notification_content.append("\n-------------------------------")

        try:
            print(f"📑 processing {account.name}")
            checkin = CheckIn(account.name, global_proxy=global_proxy, debug=debug)
            success, result = await checkin.execute(
                sid=account.sid or None,
                tier=tier,
                credential=account.credential,
            )

            if success:
                success_count += 1
                current_info[account.name] = result
                source = result.get("auth_source", "unknown")
                if result.get("already_signed"):
                    notification_content.append(
                        f"  🔵 {account.name}: already signed [{source}] | reward {result.get('reward_final', '?')} ({result.get('tier_name', '')})"
                    )
                else:
                    notification_content.append(
                        f"  🔵 {account.name}: reward {result.get('reward_final', '?')} ({result.get('tier_name', '')}) | PoW {result.get('pow_elapsed', '?')}s @ {result.get('pow_hps', 0):,} H/s [{source}]"
                    )
                if result.get("sid_refreshed"):
                    notification_content.append(f"    ↳ sid refreshed via linuxdo ({result.get('login_message', '')})")
            else:
                error_msg = result.get("error", "unknown error") if result else "unknown error"
                notification_content.append(f"  ❌ {account.name}: {error_msg}")

        except Exception as exc:
            print(f"❌ {account.name} exception: {exc}")
            notification_content.append(f"  ❌ {account.name} exception: {str(exc)[:120]}")

    current_hash = generate_checkin_hash(current_info)
    print(f"\nℹ️ current hash: {current_hash}, last hash: {last_hash}")

    need_notify = False
    if not last_hash:
        need_notify = True
        print("🔔 first run, notify")
    elif current_hash != last_hash:
        need_notify = True
        print("🔔 hash changed, notify")
    else:
        print("ℹ️ hash unchanged, skip notification")

    if need_notify and notification_content:
        summary = [
            "-------------------------------",
            "📙 qaq.al summary:",
            f"🟢 success: {success_count}/{total_count}",
            f"🔴 failed: {total_count - success_count}/{total_count}",
        ]
        if success_count == total_count:
            summary.append("✅ all accounts succeeded")
        elif success_count > 0:
            summary.append("⚠️ partial success")
        else:
            summary.append("❌ all accounts failed")

        time_info = f"🕘 run at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        notify_content = "\n\n".join(
            [time_info, "📋 details:\n" + "\n".join(notification_content), "\n".join(summary)]
        )

        print(notify_content)
        if success_count == total_count:
            notify.push_message("qaq.al check-in success", notify_content, msg_type="text")
            print("🔔 success notification sent")
        else:
            notify.push_message("qaq.al check-in alert", notify_content, msg_type="text")
            print("🔔 alert notification sent")

    if current_hash:
        save_balance_hash(CHECKIN_HASH_FILE, current_hash)

    sys.exit(0 if success_count > 0 else 1)


def run_main():
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n⚠️ interrupted")
        sys.exit(1)
    except Exception as exc:
        print(f"\n❌ fatal error: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    run_main()
