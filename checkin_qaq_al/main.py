#!/usr/bin/env python3
"""
qaq.al auto check-in entrypoint.

Authentication strategy per account:
1) LinuxDo login + cached storage-state fallback
2) sid fallback (if provided or cached)
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv

from checkin import CheckIn, LinuxDoCredential

sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.balance_hash import load_balance_hash, save_balance_hash
from utils.encoding import ensure_utf8_stdio
from utils.notify import notify
from utils.summary_notify import build_summary_html, build_summary_message

ensure_utf8_stdio()
load_dotenv(override=True, encoding="utf-8")

CHECKIN_HASH_FILE = "balance_hash_qaq_al.txt"


@dataclass
class AccountConfig:
    name: str
    sid: str
    credential: LinuxDoCredential | None
    tier: int = 4


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


def _to_positive_int(value, default: int) -> int:
    try:
        parsed = int(str(value).strip())
        return parsed if parsed > 0 else default
    except Exception:
        return default


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
        print("ACCOUNTS_QAQ_AL is empty")
        return None

    global_linuxdo = _load_global_linuxdo_accounts()

    try:
        normalized = _strip_code_fence(raw.lstrip("\ufeff"))
        if normalized.startswith("[") or normalized.startswith("{"):
            parsed = _parse_json_tolerant(normalized)
            if isinstance(parsed, dict):
                if "ACCOUNTS_QAQ_AL" not in parsed:
                    print("ACCOUNTS_QAQ_AL is a JSON object but key ACCOUNTS_QAQ_AL is missing")
                    return None
                parsed = parsed["ACCOUNTS_QAQ_AL"]
            if not isinstance(parsed, list):
                print("ACCOUNTS_QAQ_AL must be a JSON array")
                return None
            source_items = parsed
        else:
            # Backward compatibility: comma-separated sid string.
            source_items = [s.strip() for s in normalized.split(",") if s.strip()]
    except Exception as exc:
        print(f"Failed to parse ACCOUNTS_QAQ_AL: {exc}")
        return None

    accounts: list[AccountConfig] = []
    for idx, item in enumerate(source_items):
        name = f"account_{idx + 1}"
        sid = ""
        credential: LinuxDoCredential | None = None
        tier = 4

        if isinstance(item, str):
            sid = item.strip().strip('"').strip("'")
        elif isinstance(item, dict):
            name = str(item.get("name") or name)
            tier = _to_positive_int(item.get("tier", 4), default=4)
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
            print(f"Skip {name}: missing sid and linuxdo credential")
            continue

        accounts.append(AccountConfig(name=name, sid=sid, credential=credential, tier=tier))

    if not accounts:
        print("No valid qaq.al account configuration")
        return None

    print(f"Loaded {len(accounts)} qaq.al account(s)")
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


def _resolve_cache_status(auth_source: str, login_message: str, error_message: str) -> str:
    source = str(auth_source or "").strip().lower()
    login_text = str(login_message or "").strip().lower()
    error_text = str(error_message or "").strip().lower()

    if source == "sid_cache_fallback" or "sid_cache_fallback" in error_text:
        return "hit"
    if source == "sid_storage_state_fallback" or "sid_storage_state_fallback" in error_text:
        return "stale"
    if source == "sid_fallback" or "sid_fallback" in error_text:
        return "miss"
    if source == "linuxdo":
        if "restored from cache" in login_text:
            return "hit"
        return "miss"
    return "-"


def _to_float(value) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        text = value.strip().replace(",", "")
        if not text:
            return None
        if re.fullmatch(r"[-+]?\d+(?:\.\d+)?", text):
            try:
                return float(text)
            except ValueError:
                return None
    return None


def _format_number(value: float | None, fallback: str = "unknown") -> str:
    if value is None:
        return fallback
    rounded = round(value, 4)
    if rounded.is_integer():
        return str(int(rounded))
    return f"{rounded:.4f}".rstrip("0").rstrip(".")


def _build_success_detail(result: dict) -> str:
    source = str(result.get("auth_source", "unknown"))
    reward_value = _to_float(result.get("reward_final"))
    reward_text = _format_number(reward_value, fallback=str(result.get("reward_final", "?")))
    tier_name = str(result.get("tier_name", "-"))
    if result.get("already_signed"):
        return f"checkin:+0 (already); last_reward={reward_text}; tier={tier_name}; source={source}"

    base_value = _to_float(result.get("reward_base"))
    multiplier = str(result.get("multiplier", "-"))
    pow_elapsed = result.get("pow_elapsed")
    pow_hps = _to_float(result.get("pow_hps"))
    notes = str(result.get("notes", "")).strip()

    parts = [
        f"checkin:+{reward_text}",
        f"tier={tier_name}",
        f"source={source}",
    ]
    if base_value is not None:
        parts.append(f"base={_format_number(base_value)}")
    if multiplier and multiplier != "-":
        parts.append(f"x{multiplier}")
    if pow_elapsed is not None and pow_hps is not None:
        parts.append(f"pow={pow_elapsed}s@{_format_number(pow_hps)}/s")
    elif pow_elapsed is not None:
        parts.append(f"pow={pow_elapsed}s")
    if notes:
        parts.append(f"notes={notes[:40]}")
    return "; ".join(parts)


async def main() -> int:
    print("qaq.al auto check-in started")
    print(f"run at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    accounts = load_accounts()
    if not accounts:
        print("Failed to load account config, exit")
        return 1

    total_count = len(accounts)
    print(f"total accounts: {total_count}")

    last_hash = load_balance_hash(CHECKIN_HASH_FILE)
    if last_hash:
        print(f"last check-in hash: {last_hash}")
    else:
        print("first run, no previous hash")

    global_proxy = None
    proxy_str = os.getenv("PROXY")
    if proxy_str:
        try:
            global_proxy = json.loads(proxy_str)
            print("proxy loaded as dict")
        except json.JSONDecodeError:
            global_proxy = {"server": proxy_str}
            print(f"proxy loaded as url: {proxy_str}")

    debug = _to_bool(os.getenv("DEBUG", "false"), default=False)
    notify_format = _normalize_notify_format(os.getenv("QAQ_AL_NOTIFY_FORMAT"), default="both")
    print(f"debug={debug}, notify_format={notify_format}")

    success_count = 0
    detail_lines: list[str] = []
    current_info: dict = {}
    failed_accounts: list[str] = []
    highlight_accounts: list[str] = []
    auth_rows: list[dict[str, str]] = []

    for account in accounts:
        try:
            print(f"processing {account.name} (tier={account.tier})")
            checkin = CheckIn(account.name, global_proxy=global_proxy, debug=debug)
            success, result = await checkin.execute(
                sid=account.sid or None,
                tier=account.tier,
                credential=account.credential,
            )

            if not isinstance(result, dict):
                result = {"error": "invalid result payload"}

            auth_source = str(result.get("auth_source", "qaq.al"))
            error_msg = str(result.get("error", "unknown error"))
            login_message = str(result.get("login_message", ""))
            cache_status = _resolve_cache_status(auth_source, login_message, error_msg)

            if success:
                success_count += 1
                current_info[account.name] = result
                detail = _build_success_detail(result)
                auth_rows.append(
                    {
                        "account": account.name,
                        "method": auth_source,
                        "cache": cache_status,
                        "result": "ok",
                        "detail": detail[:280],
                    }
                )
                highlight_accounts.append(f"{account.name}(ok:{auth_source})")
                detail_lines.append(f"OK {account.name}: {detail}")
                if result.get("sid_refreshed"):
                    detail_lines.append(f"  sid refreshed via linuxdo ({login_message or 'updated'})")
            else:
                auth_rows.append(
                    {
                        "account": account.name,
                        "method": auth_source,
                        "cache": cache_status,
                        "result": "fail",
                        "detail": error_msg[:280] or "unknown error",
                    }
                )
                failed_accounts.append(f"{account.name}({error_msg[:80] or 'unknown error'})")
                detail_lines.append(f"FAIL {account.name}: {error_msg}")

        except Exception as exc:
            err = str(exc)[:160]
            print(f"{account.name} exception: {err}")
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
            detail_lines.append(f"FAIL {account.name}: exception: {err}")

    current_hash = generate_checkin_hash(current_info)
    print(f"current hash: {current_hash}, last hash: {last_hash}")

    need_notify = False
    first_run = False
    balance_changed = False
    if not last_hash:
        need_notify = True
        first_run = True
        print("first run, notify")
    elif current_hash != last_hash:
        need_notify = True
        balance_changed = True
        print("hash changed, notify")
    else:
        print("hash unchanged, skip notification")

    if need_notify:
        reasons: list[str] = []
        if failed_accounts:
            reasons.append("account_failure")
        if first_run:
            reasons.append("first_run")
        if balance_changed:
            reasons.append("balance_changed")
        if not reasons:
            reasons.append("manual")

        metrics = {
            "accounts_success": f"{success_count}/{total_count}",
            "auth_methods_success": f"{success_count}/{total_count}",
        }
        summary_content = build_summary_message(
            workflow="qaq/checkin",
            success_count=success_count,
            total_count=total_count,
            metrics=metrics,
            reasons=reasons,
            failed_items=failed_accounts,
            highlight_items=highlight_accounts,
            auth_rows=auth_rows,
        )
        summary_html = build_summary_html(
            workflow="qaq/checkin",
            success_count=success_count,
            total_count=total_count,
            metrics=metrics,
            reasons=reasons,
            failed_items=failed_accounts,
            highlight_items=highlight_accounts,
            auth_rows=auth_rows,
        )

        detail_section = [
            f"time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"accounts_success: {success_count}/{total_count}",
            f"auth_methods_success: {success_count}/{total_count}",
        ]
        if detail_lines:
            detail_section.extend(["details:", *detail_lines])

        sections: list[str] = []
        if notify_format in {"detail", "both"}:
            sections.append("\n".join(detail_section))
        if notify_format in {"summary", "both"}:
            sections.append(summary_content)
        notify_content = "\n\n".join(sections) if sections else summary_content

        notify_title = "qaq.al check-in alert" if failed_accounts else "qaq.al check-in success"
        html_notify_content = summary_html if notify_format in {"summary", "both"} else None
        print(notify_content)
        notify.push_message(
            notify_title,
            notify_content,
            msg_type="text",
            html_content=html_notify_content,
        )
        print("notification sent")

    if current_hash:
        save_balance_hash(CHECKIN_HASH_FILE, current_hash)

    return 0 if success_count > 0 else 1


def run_main() -> None:
    try:
        code = asyncio.run(main())
        sys.exit(code)
    except KeyboardInterrupt:
        print("interrupted")
        sys.exit(1)
    except Exception as exc:
        print(f"fatal error: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    run_main()
