#!/usr/bin/env python3
"""
InfiniteAI auto check-in entrypoint.

Environment:
- ACCOUNTS_INFINITEAI: JSON array
- ACCOUNTS_LINUX_DO: optional global LinuxDo credentials
- PROXY_INFINITEAI: optional proxy JSON/string
- DEBUG: true/false
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).parent.parent))

from checkin_infiniteai.checkin import InfiniteAICheckIn, LinuxDoCredential, UserCredential
from utils.browser_utils import parse_cookies
from utils.encoding import ensure_utf8_stdio
from utils.notify import notify
from utils.notify_policy import get_balance_change_mode
from utils.summary_notify import build_summary_html, build_summary_message

ensure_utf8_stdio()
load_dotenv(override=True, encoding="utf-8")


@dataclass
class AccountConfig:
    name: str
    cookies: dict
    user_credential: UserCredential | None
    linuxdo_credential: LinuxDoCredential | None


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


def _parse_user_credential(value) -> UserCredential | None:
    if not isinstance(value, dict):
        return None
    username = str(value.get("username") or value.get("email") or "").strip()
    password = str(value.get("password", "")).strip()
    if username and password:
        return UserCredential(username=username, password=password)
    return None


def _load_global_linuxdo_accounts() -> list[LinuxDoCredential]:
    raw = os.getenv("ACCOUNTS_LINUX_DO", "").strip().lstrip("\ufeff")
    if not raw:
        return []

    try:
        parsed = _parse_json_tolerant(_strip_code_fence(raw))
    except Exception as exc:
        print(f"Failed to parse ACCOUNTS_LINUX_DO: {exc}")
        return []

    if not isinstance(parsed, list):
        print("ACCOUNTS_LINUX_DO must be a JSON array")
        return []

    items: list[LinuxDoCredential] = []
    for item in parsed:
        cred = _parse_linuxdo_credential(item)
        if cred:
            items.append(cred)
    return items


def _pick_linuxdo_credential(item: dict, global_accounts: list[LinuxDoCredential], index: int) -> LinuxDoCredential | None:
    for key in ("linux.do", "linuxdo"):
        if key not in item:
            continue
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
    return None


def _pick_user_credential(item: dict) -> UserCredential | None:
    user_value = item.get("user")
    if isinstance(user_value, dict):
        parsed = _parse_user_credential(user_value)
        if parsed:
            return parsed
    if isinstance(user_value, list):
        for row in user_value:
            parsed = _parse_user_credential(row)
            if parsed:
                return parsed
    # Backward-compatible direct username/password
    return _parse_user_credential(item)


def load_accounts() -> list[AccountConfig]:
    raw = os.getenv("ACCOUNTS_INFINITEAI", "").strip()
    if not raw:
        print("ACCOUNTS_INFINITEAI is empty")
        return []

    global_linuxdo = _load_global_linuxdo_accounts()

    try:
        normalized = _strip_code_fence(raw.lstrip("\ufeff"))
        parsed = _parse_json_tolerant(normalized)
        if isinstance(parsed, dict):
            if "ACCOUNTS_INFINITEAI" in parsed:
                parsed = parsed["ACCOUNTS_INFINITEAI"]
        if not isinstance(parsed, list):
            print("ACCOUNTS_INFINITEAI must be a JSON array")
            return []
        source_items = parsed
    except Exception as exc:
        print(f"Failed to parse ACCOUNTS_INFINITEAI: {exc}")
        return []

    accounts: list[AccountConfig] = []
    for idx, item in enumerate(source_items):
        name = f"infiniteai_{idx + 1}"
        cookies: dict = {}
        user_credential: UserCredential | None = None
        linuxdo_credential: LinuxDoCredential | None = None

        if isinstance(item, str):
            cookies = parse_cookies(item)
        elif isinstance(item, dict):
            name = str(item.get("name") or name)
            raw_cookies = item.get("cookies")
            if raw_cookies is None:
                raw_cookies = item.get("cookie")
            if raw_cookies is None and item.get("session"):
                raw_cookies = {"session": item.get("session")}
            cookies = parse_cookies(raw_cookies) if raw_cookies is not None else {}

            user_credential = _pick_user_credential(item)
            linuxdo_credential = _pick_linuxdo_credential(item, global_linuxdo, idx)
        else:
            continue

        if not cookies and user_credential is None and linuxdo_credential is None and global_linuxdo:
            linuxdo_credential = global_linuxdo[idx] if idx < len(global_linuxdo) else global_linuxdo[0]

        if not cookies and user_credential is None and linuxdo_credential is None:
            print(f"Skip {name}: no cookies, user, or linuxdo credential")
            continue

        accounts.append(
            AccountConfig(
                name=name,
                cookies=cookies,
                user_credential=user_credential,
                linuxdo_credential=linuxdo_credential,
            )
        )

    if not accounts:
        print("No valid infiniteai account configuration")
    return accounts


def load_proxy() -> dict | None:
    raw = os.getenv("PROXY_INFINITEAI", "").strip() or os.getenv("PROXY", "").strip()
    if not raw:
        return None
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass
    return {"server": raw}


def _infer_cache(details: list[str]) -> str:
    for raw in details:
        line = str(raw).lower()
        if "[cache] storage-state hit" in line:
            return "hit"
        if "[cache] storage-state miss" in line:
            return "miss"
        if "[cache] restore failed" in line:
            return "stale"
    return "-"


def _normalize_details(raw_details) -> list[str]:
    if not isinstance(raw_details, list):
        return []
    return [str(item) for item in raw_details]


def _format_number(value: float | None) -> str:
    if value is None:
        return "unknown"
    rounded = round(value, 4)
    if rounded.is_integer():
        return str(int(rounded))
    return f"{rounded:.4f}".rstrip("0").rstrip(".")


def _build_success_detail(data: dict) -> str:
    checkin_result = data.get("checkin_result") if isinstance(data.get("checkin_result"), dict) else {}
    snapshot = data.get("session_snapshot") if isinstance(data.get("session_snapshot"), dict) else {}
    auth_source = str(data.get("auth_source", "infiniteai"))

    already = bool(checkin_result.get("already"))
    reward_text = "unknown"
    reward_value = checkin_result.get("reward")
    if isinstance(reward_value, (int, float)):
        reward_text = _format_number(float(reward_value))

    if already:
        checkin_part = "checkin:+0 (already)"
    else:
        checkin_part = f"checkin:+{reward_text}" if reward_text != "unknown" else "checkin:ok"

    balance = snapshot.get("balance")
    claims = snapshot.get("total_claims")
    message = str(checkin_result.get("message", "")).strip()

    parts = [
        checkin_part,
        f"source={auth_source}",
    ]
    if isinstance(balance, (int, float)):
        parts.append(f"balance={_format_number(float(balance))}")
    if isinstance(claims, (int, float)):
        parts.append(f"claims={_format_number(float(claims))}")
    if message:
        parts.append(f"msg={message[:60]}")
    return "; ".join(parts)


def _build_failure_detail(data: dict) -> str:
    error_text = str(data.get("error", "unknown error"))
    checkin_result = data.get("checkin_result")
    parts = [error_text]
    if isinstance(checkin_result, dict):
        extra = str(checkin_result.get("error") or checkin_result.get("message") or "").strip()
        if extra:
            parts.append(f"checkin={extra}")
    return "; ".join(parts)


async def main() -> int:
    print("infiniteai automation started")
    print(f"run at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    accounts = load_accounts()
    if not accounts:
        print("No valid infiniteai account config")
        return 1

    proxy = load_proxy()
    debug = _to_bool(os.getenv("DEBUG", "false"), default=False)
    balance_change_mode = get_balance_change_mode()
    print(f"balance_change_mode={balance_change_mode} (not used by infiniteai workflow)")

    success_count = 0
    total_count = len(accounts)
    auth_rows: list[dict[str, str]] = []
    failed_accounts: list[str] = []
    highlight_accounts: list[str] = []

    for account in accounts:
        checker = InfiniteAICheckIn(
            account_name=account.name,
            cookies=account.cookies,
            user_credential=account.user_credential,
            linuxdo_credential=account.linuxdo_credential,
            proxy=proxy,
            debug=debug,
        )

        try:
            ok, data = await checker.execute()
            if not isinstance(data, dict):
                data = {"error": "invalid result payload"}
            details = _normalize_details(data.get("details"))
            method = str(data.get("auth_source") or "infiniteai")
            cache_status = _infer_cache(details)

            if ok:
                success_count += 1
                detail = _build_success_detail(data)
                auth_rows.append(
                    {
                        "account": account.name,
                        "method": method,
                        "cache": cache_status,
                        "result": "ok",
                        "detail": detail[:280],
                    }
                )
                highlight_accounts.append(f"{account.name}(ok:{method})")
            else:
                fail_detail = _build_failure_detail(data)
                auth_rows.append(
                    {
                        "account": account.name,
                        "method": method,
                        "cache": cache_status,
                        "result": "fail",
                        "detail": fail_detail[:280],
                    }
                )
                failed_accounts.append(f"{account.name}({fail_detail[:80]})")
        except Exception as exc:
            err = str(exc)[:160]
            auth_rows.append(
                {
                    "account": account.name,
                    "method": "runtime",
                    "cache": "-",
                    "result": "fail",
                    "detail": err or "runtime exception",
                }
            )
            failed_accounts.append(f"{account.name}(exception: {err[:80]})")

    has_account_failure = bool(failed_accounts)
    has_partial_failure = has_account_failure and success_count > 0

    reasons: list[str] = []
    if has_account_failure:
        reasons.append("account_failure")
    if has_partial_failure:
        reasons.append("partial_failure")
    if not reasons:
        reasons.append("scheduled_run")

    metrics = {
        "accounts_success": f"{success_count}/{total_count}",
        "auth_methods_success": f"{success_count}/{total_count}",
    }
    summary_content = build_summary_message(
        workflow="infiniteai/checkin",
        success_count=success_count,
        total_count=total_count,
        metrics=metrics,
        reasons=reasons,
        failed_items=failed_accounts,
        highlight_items=highlight_accounts,
        auth_rows=auth_rows,
    )
    summary_html = build_summary_html(
        workflow="infiniteai/checkin",
        success_count=success_count,
        total_count=total_count,
        metrics=metrics,
        reasons=reasons,
        failed_items=failed_accounts,
        highlight_items=highlight_accounts,
        auth_rows=auth_rows,
    )

    title = "infiniteai automation alert" if has_account_failure else "infiniteai automation"
    print(summary_content)
    notify.push_message(title, summary_content, msg_type="text", html_content=summary_html)
    return 0 if success_count > 0 else 1


def run_main() -> None:
    try:
        code = asyncio.run(main())
        sys.exit(code)
    except KeyboardInterrupt:
        print("Interrupted")
        sys.exit(1)
    except Exception as exc:
        print(f"Fatal error: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    run_main()
