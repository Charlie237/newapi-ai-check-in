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

    items = []
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
            # Fallback: if account has neither cookies nor explicit credential,
            # use global LinuxDo account by index/first.
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


async def main() -> int:
    print("hybgzs automation started")
    print(f"run at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    accounts = load_accounts()
    if not accounts:
        print("No valid hybgzs account config")
        return 1

    proxy = load_proxy()
    debug = _to_bool(os.getenv("DEBUG", "false"), default=False)
    notify_format = _normalize_notify_format(os.getenv("HYBGZS_NOTIFY_FORMAT"), default="both")

    success_count = 0
    lines: list[str] = []

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

        ok, data = await checker.execute()
        if ok:
            success_count += 1
            lines.append(f"OK {account.name}: {data.get('display', 'done')}")
        else:
            lines.append(f"FAIL {account.name}: {data.get('error', 'unknown error')}")

        for detail in data.get("details", []):
            lines.append(f"  - {detail}")

    total = len(accounts)
    summary = [
        "-------------------------------",
        "hybgzs result summary:",
        f"success: {success_count}/{total}",
        f"failed: {total - success_count}/{total}",
    ]

    if success_count == total:
        summary.append("all accounts succeeded")
    elif success_count > 0:
        summary.append("partial success")
    else:
        summary.append("all accounts failed")

    sections = [f"time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"]
    if notify_format in {"detail", "both"}:
        sections.extend(
            [
                "",
                "details:",
                *(lines if lines else ["-"]),
            ]
        )
    if notify_format in {"summary", "both"}:
        sections.extend(["", *summary])
    report = "\n".join(sections)

    print(report)
    notify.push_message("hybgzs automation", report, msg_type="text")
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
