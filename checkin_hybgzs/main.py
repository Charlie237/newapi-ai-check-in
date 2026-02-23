#!/usr/bin/env python3
"""
Standalone hybgzs check-in entrypoint.

Environment:
- ACCOUNTS_HYBGZS: JSON array
- ACCOUNTS_LINUX_DO: optional global LinuxDo credentials
- PROXY_HYBGZS: optional proxy JSON/string
- DEBUG: true/false
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).parent.parent))

from checkin_hybgzs.checkin import HybgzsCheckIn, LinuxDoCredential
from utils.browser_utils import parse_cookies
from utils.encoding import ensure_utf8_stdio
from utils.notify import notify
from utils.summary_notify import build_summary_html, build_summary_message

ensure_utf8_stdio()
load_dotenv(override=True, encoding="utf-8")


@dataclass
class AccountConfig:
    name: str
    cookies: dict
    credential: LinuxDoCredential | None
    run_wheel: bool
    max_wheel_spins: int = 0


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


def _to_bool(value, default: bool = True) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        v = value.strip().lower()
        if v in {"1", "true", "yes", "on"}:
            return True
        if v in {"0", "false", "no", "off"}:
            return False
    return default


def _to_non_negative_int(value, default: int = 0) -> int:
    try:
        parsed = int(str(value).strip())
    except Exception:
        return default
    return parsed if parsed >= 0 else default


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


def load_accounts() -> list[AccountConfig]:
    raw = os.getenv("ACCOUNTS_HYBGZS", "").strip()
    if not raw:
        print("ACCOUNTS_HYBGZS is empty")
        return []

    global_linuxdo = _load_global_linuxdo_accounts()

    try:
        parsed = _parse_json_tolerant(_strip_code_fence(raw.lstrip("\ufeff")))
    except Exception as exc:
        print(f"Failed to parse ACCOUNTS_HYBGZS: {exc}")
        return []

    if not isinstance(parsed, list):
        print("ACCOUNTS_HYBGZS must be a JSON array")
        return []

    result: list[AccountConfig] = []
    for idx, item in enumerate(parsed):
        name = f"hybgzs_{idx + 1}"
        cookies = {}
        credential = None
        run_wheel = True
        max_wheel_spins = 0

        if isinstance(item, str):
            cookies = parse_cookies(item)
        elif isinstance(item, dict):
            name = str(item.get("name") or name)
            cookies = parse_cookies(item.get("cookies", ""))
            credential = _pick_credential(item, global_linuxdo, idx)
            run_wheel = _to_bool(item.get("wheel"), default=True)
            max_wheel_spins = _to_non_negative_int(item.get("max_wheel_spins", 0), default=0)
        else:
            continue

        if not cookies and credential is None and global_linuxdo:
            credential = global_linuxdo[idx] if idx < len(global_linuxdo) else global_linuxdo[0]

        if not cookies and credential is None:
            print(f"Skip {name}: no cookies and no LinuxDo credential")
            continue

        result.append(
            AccountConfig(
                name=name,
                cookies=cookies,
                credential=credential,
                run_wheel=run_wheel,
                max_wheel_spins=max_wheel_spins,
            )
        )

    return result


def load_proxy() -> dict | None:
    raw = os.getenv("PROXY_HYBGZS", "").strip()
    if not raw:
        return None
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass
    return {"server": raw}


def _infer_method(details: list[str]) -> str:
    text = "\n".join(str(item) for item in details).lower()
    if "credential flow" in text or "linuxdo" in text:
        return "linux.do"
    if "session restored from cookies" in text:
        return "cookies"
    if "session restored from storage-state cache" in text:
        return "storage-state"
    return "hybgzs"


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


def _extract_first_number(text: str) -> float | None:
    if not text:
        return None
    for match in re.finditer(r"[-+]?\d+(?:\.\d+)?", text.replace(",", "")):
        try:
            return float(match.group(0))
        except ValueError:
            continue
    return None


def _format_number(value: float | None) -> str:
    if value is None:
        return "unknown"
    rounded = round(value, 4)
    if rounded.is_integer():
        return str(int(rounded))
    return f"{rounded:.4f}".rstrip("0").rstrip(".")


def _extract_amount_from_mapping(payload: dict) -> float | None:
    key_hints = ("amount", "reward", "coin", "point", "credit", "value", "score")
    for key, raw in payload.items():
        key_text = str(key).strip().lower()
        if not key_text:
            continue
        if any(hint in key_text for hint in key_hints):
            parsed = _to_float(raw)
            if parsed is not None:
                return parsed
            parsed = _extract_first_number(str(raw))
            if parsed is not None:
                return parsed
    return None


def _extract_checkin_gain(checkin_result: dict | None) -> float | None:
    if not isinstance(checkin_result, dict):
        return None
    if checkin_result.get("already") or checkin_result.get("skipped") or checkin_result.get("maintenance"):
        return 0.0

    parsed = _extract_amount_from_mapping(checkin_result)
    if parsed is not None:
        return parsed
    return _extract_first_number(str(checkin_result.get("message", "")))


def _extract_spin_gain(spin: dict) -> float | None:
    parsed = _to_float(spin.get("prize_amount"))
    if parsed is not None:
        return parsed

    prize = spin.get("prize")
    if isinstance(prize, dict):
        parsed = _extract_amount_from_mapping(prize)
        if parsed is not None:
            return parsed

    parsed = _extract_first_number(str(spin.get("message", "")))
    if parsed is not None:
        return parsed
    return _extract_first_number(str(spin.get("prize_name", "")))


def _build_wheel_summary(wheel_result: dict | None) -> tuple[str, float | None, int, list[str]]:
    if not isinstance(wheel_result, dict):
        return "wheel:+unknown", None, 0, []

    if wheel_result.get("skipped"):
        return "wheel:+0 (skipped)", 0.0, 0, []

    results = wheel_result.get("results")
    if not isinstance(results, list):
        results = []
    spins = wheel_result.get("spins")
    if not isinstance(spins, int):
        spins = len(results)

    if spins <= 0 and not results:
        return "wheel:+0 (spins=0)", 0.0, 0, []

    total = 0.0
    known_count = 0
    spin_summaries: list[str] = []
    for idx, item in enumerate(results):
        spin = item if isinstance(item, dict) else {}
        gain = _extract_spin_gain(spin)
        if gain is not None:
            total += gain
            known_count += 1
        prize_name = str(spin.get("prize_name") or spin.get("message") or f"spin_{idx + 1}").strip()
        if len(prize_name) > 24:
            prize_name = prize_name[:21] + "..."
        gain_label = f"+{_format_number(gain)}" if gain is not None else "+unknown"
        spin_summaries.append(f"{idx + 1}:{prize_name}({gain_label})")

    amount_count = len(results)
    if amount_count == 0:
        message = str(wheel_result.get("message", "")).strip()
        return f"wheel:+0 ({message or 'no-result'})", 0.0, spins, []

    if known_count == amount_count:
        return f"wheel:+{_format_number(total)} (spins={spins})", total, spins, spin_summaries
    if known_count > 0:
        return (
            f"wheel:>=+{_format_number(total)} (spins={spins}, parsed={known_count}/{amount_count})",
            None,
            spins,
            spin_summaries,
        )
    return f"wheel:+unknown (spins={spins})", None, spins, spin_summaries


def _build_hyb_success_detail(data: dict) -> str:
    checkin_result = data.get("checkin_result") if isinstance(data.get("checkin_result"), dict) else {}
    wheel_result = data.get("wheel_result") if isinstance(data.get("wheel_result"), dict) else {}

    checkin_gain = _extract_checkin_gain(checkin_result)
    if checkin_result.get("already"):
        checkin_part = "checkin:+0 (already)"
    elif checkin_result.get("skipped") or checkin_result.get("maintenance"):
        checkin_part = "checkin:+0 (skipped)"
    elif checkin_gain is None:
        checkin_part = "checkin:+unknown"
    else:
        checkin_part = f"checkin:+{_format_number(checkin_gain)}"

    wheel_part, wheel_gain, _, spin_summaries = _build_wheel_summary(wheel_result)
    if checkin_gain is not None and wheel_gain is not None:
        total_part = f"total:+{_format_number(checkin_gain + wheel_gain)}"
    else:
        total_part = "total:+unknown"

    preview = ""
    if spin_summaries:
        shown = spin_summaries[:3]
        extra = len(spin_summaries) - len(shown)
        preview = "; spins=" + ", ".join(shown)
        if extra > 0:
            preview += f", +{extra} more"

    return f"{checkin_part}; {wheel_part}; {total_part}{preview}"


def _build_hyb_failure_detail(data: dict) -> str:
    error_text = str(data.get("error", "unknown error"))
    checkin_result = data.get("checkin_result")
    wheel_result = data.get("wheel_result")

    parts = [error_text]
    if isinstance(checkin_result, dict):
        checkin_msg = str(checkin_result.get("error") or checkin_result.get("message") or "").strip()
        if checkin_msg:
            parts.append(f"checkin={checkin_msg}")
    if isinstance(wheel_result, dict):
        wheel_msg = str(wheel_result.get("error") or wheel_result.get("message") or "").strip()
        if wheel_msg:
            parts.append(f"wheel={wheel_msg}")

    return "; ".join(parts)


async def main() -> int:
    print("hybgzs automation started")
    print(f"run at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    accounts = load_accounts()
    if not accounts:
        print("No valid hybgzs account config")
        return 1

    proxy = load_proxy()
    debug = _to_bool(os.getenv("DEBUG", "false"), default=False)

    success_count = 0
    total_count = len(accounts)
    auth_rows: list[dict[str, str]] = []
    failed_accounts: list[str] = []
    highlight_accounts: list[str] = []

    for account in accounts:
        checker = HybgzsCheckIn(
            account_name=account.name,
            cookies=account.cookies,
            credential=account.credential,
            proxy=proxy,
            run_wheel=account.run_wheel,
            max_wheel_spins=account.max_wheel_spins,
            debug=debug,
        )

        try:
            ok, data = await checker.execute()
            if not isinstance(data, dict):
                data = {"error": "invalid result payload"}

            details = _normalize_details(data.get("details"))
            method = _infer_method(details)
            cache_status = _infer_cache(details)

            if ok:
                success_count += 1
                detail = _build_hyb_success_detail(data)
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
                fail_detail = _build_hyb_failure_detail(data)
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
        workflow="hybgzs/checkin",
        success_count=success_count,
        total_count=total_count,
        metrics=metrics,
        reasons=reasons,
        failed_items=failed_accounts,
        highlight_items=highlight_accounts,
        auth_rows=auth_rows,
    )
    summary_html = build_summary_html(
        workflow="hybgzs/checkin",
        success_count=success_count,
        total_count=total_count,
        metrics=metrics,
        reasons=reasons,
        failed_items=failed_accounts,
        highlight_items=highlight_accounts,
        auth_rows=auth_rows,
    )

    report = summary_content

    title = "hybgzs automation alert" if has_account_failure else "hybgzs automation"
    print(report)
    notify.push_message(
        title,
        report,
        msg_type="text",
        html_content=summary_html,
    )
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
