#!/usr/bin/env python3
"""
qaq.al check-in runner.

Authentication priority:
1) LinuxDo login with storage-state cache restore.
2) Fallback to provided sid.
3) Fallback to cached sid.
"""

from __future__ import annotations

import hashlib
import json
import os
import statistics
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from camoufox.async_api import AsyncCamoufox
from curl_cffi import requests as curl_requests
from playwright_captcha import CaptchaType, ClickSolver, FrameworkType

sys.path.insert(0, str(Path(__file__).parent.parent))
from utils.get_cf_clearance import get_cf_clearance
from utils.get_headers import get_curl_cffi_impersonate
from utils.http_utils import proxy_resolve, response_resolve

BASE_URL = "https://sign.qaq.al"
BENCH_ROUNDS = 3
BENCH_DURATION_MS = 1200

LOGIN_BUTTON_SELECTORS = [
    "a[href='/auth/login']",
    "a[href*='/auth/login']",
    "a[href*='connect.linux.do']",
    "a[href*='linuxdo']",
    "a[href*='linux.do']",
    "button:has-text('LinuxDo')",
    "a:has-text('LinuxDo')",
    "button:has-text('LINUXDO')",
    "a:has-text('LINUXDO')",
    "a:has-text('LinuxDO')",
    "a:has-text('Linux.do')",
]

APPROVE_BUTTON_SELECTOR = "a[href^='/oauth2/approve']"


@dataclass
class LinuxDoCredential:
    username: str
    password: str


def count_leading_zero_bits(hash_bytes: bytes) -> int:
    """Count leading zero bits."""
    count = 0
    for byte in hash_bytes:
        if byte == 0:
            count += 8
        else:
            b = byte
            while (b & 0x80) == 0 and count < 256:
                count += 1
                b <<= 1
            break
    return count


def benchmark_hps() -> int:
    """Benchmark local SHA-256 HPS."""
    print("⚙️ Benchmarking local HPS...")
    challenge_prefix = b"benchmark:"
    samples: list[int] = []

    for i in range(BENCH_ROUNDS):
        nonce = 0
        start = time.time()
        end_time = start + BENCH_DURATION_MS / 1000

        while time.time() < end_time:
            hashlib.sha256(challenge_prefix + str(nonce).encode()).digest()
            nonce += 1

        elapsed = time.time() - start
        hps = round(nonce / elapsed) if elapsed > 0 else 0
        samples.append(hps)
        print(f"  round {i + 1}/{BENCH_ROUNDS}: {hps:,} H/s")

    final_hps = round(statistics.median(samples))
    print(f"  final median: {final_hps:,} H/s")
    return final_hps


def calculate_nonce(challenge: str, difficulty: int) -> dict:
    """Calculate PoW nonce."""
    print(f"  solving PoW nonce (difficulty={difficulty})...")
    challenge_prefix = (challenge + ":").encode()
    nonce = 0
    start = time.time()
    last_report = 0

    while True:
        hash_bytes = hashlib.sha256(challenge_prefix + str(nonce).encode()).digest()
        leading = count_leading_zero_bits(hash_bytes)

        if nonce - last_report >= 100000:
            last_report = nonce
            elapsed = time.time() - start
            hps = round(nonce / elapsed) if elapsed > 0 else 0
            print(f"    progress nonce={nonce:,}, leading={leading}, {hps:,} H/s, {elapsed:.1f}s")

        if leading >= difficulty:
            elapsed = time.time() - start
            hps = round(nonce / elapsed) if elapsed > 0 else 0
            print(f"  found nonce={nonce}, leading={leading}, elapsed={elapsed:.1f}s, {hps:,} H/s")
            return {
                "nonce": nonce,
                "leading": leading,
                "hash": hash_bytes.hex(),
                "elapsed": round(elapsed, 1),
                "hps": hps,
            }

        nonce += 1


class CheckIn:
    """qaq.al PoW check-in manager."""

    def __init__(
        self,
        account_name: str,
        global_proxy: dict | None = None,
        storage_state_dir: str = "storage-states",
        debug: bool = False,
    ):
        self.account_name = account_name
        self.global_proxy = global_proxy
        self.http_proxy_config = proxy_resolve(global_proxy)
        self.camoufox_proxy_config = global_proxy if global_proxy else None
        self.storage_state_dir = storage_state_dir
        self.sid_cache_path = os.path.join(self.storage_state_dir, "qaq_al_sid_cache.json")
        self.debug = debug
        os.makedirs(self.storage_state_dir, exist_ok=True)

    def _build_sid_cache_key(self, credential: LinuxDoCredential | None) -> str:
        if credential and credential.username:
            username_hash = hashlib.sha256(credential.username.encode("utf-8")).hexdigest()[:16]
            return f"linuxdo:{username_hash}"
        account_hash = hashlib.sha256(self.account_name.encode("utf-8")).hexdigest()[:16]
        return f"account:{account_hash}"

    def _load_sid_cache(self) -> dict[str, str]:
        if not os.path.exists(self.sid_cache_path):
            return {}
        try:
            with open(self.sid_cache_path, encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                return {str(k): str(v) for k, v in data.items() if isinstance(v, str) and v}
        except Exception:
            pass
        return {}

    def _read_cached_sid(self, cache_key: str) -> str:
        sid = self._load_sid_cache().get(cache_key, "").strip()
        if sid:
            print(f"  {self.account_name}: sid cache hit")
        else:
            print(f"  {self.account_name}: sid cache miss")
        return sid

    def _save_cached_sid(self, cache_key: str, sid: str) -> None:
        sid_value = str(sid or "").strip()
        if not sid_value:
            return
        try:
            cache = self._load_sid_cache()
            if cache.get(cache_key) == sid_value:
                return
            cache[cache_key] = sid_value
            tmp_path = f"{self.sid_cache_path}.tmp"
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(cache, f, ensure_ascii=False, indent=2)
            os.replace(tmp_path, self.sid_cache_path)
            print(f"  {self.account_name}: sid cache updated")
        except Exception as exc:
            print(f"  {self.account_name}: sid cache save failed: {exc}")

    async def _get_cf_clearance(self) -> tuple[dict | None, dict | None]:
        """Get cf_clearance and browser fingerprint headers."""
        print(f"  {self.account_name}: acquiring cf_clearance...")
        try:
            cf_cookies, browser_headers = await get_cf_clearance(
                url=f"{BASE_URL}/app",
                account_name=self.account_name,
                proxy_config=self.camoufox_proxy_config,
            )
            if cf_cookies and "cf_clearance" in cf_cookies:
                print(f"  {self.account_name}: cf_clearance acquired")
            else:
                print(f"  {self.account_name}: cf_clearance missing")
            return cf_cookies, browser_headers
        except Exception as exc:
            print(f"  {self.account_name}: failed to get cf_clearance: {exc}")
            return None, None

    def _build_session(
        self,
        sid: str,
        cf_cookies: dict | None,
        browser_headers: dict | None,
    ) -> curl_requests.Session:
        """Create request session with sid + cf cookies."""
        impersonate = "chrome"
        if browser_headers and browser_headers.get("User-Agent"):
            impersonate = get_curl_cffi_impersonate(browser_headers["User-Agent"])
            print(f"  {self.account_name}: impersonate={impersonate}")

        session = curl_requests.Session(
            proxy=self.http_proxy_config,
            timeout=30,
            impersonate=impersonate,
        )

        session.cookies.set("sid", sid, domain="sign.qaq.al")
        if cf_cookies:
            for name, value in cf_cookies.items():
                session.cookies.set(name, value, domain="sign.qaq.al")

        if browser_headers:
            session.headers.update(browser_headers)

        return session

    def _check_me(self, session: curl_requests.Session) -> tuple[dict | None, str]:
        """Call /api/me and return (data, error)."""
        print(f"  {self.account_name}: checking /api/me ...")
        try:
            resp = session.get(f"{BASE_URL}/api/me", timeout=30)
            if resp.status_code in (401, 403):
                return None, f"unauthorized http={resp.status_code}"

            data = response_resolve(resp, "check_me", self.account_name)
            if data and "user" in data:
                user = data["user"]
                print(f"  {self.account_name}: user {user.get('name', '?')} ({user.get('username', '?')})")
                return data, ""

            if isinstance(data, dict):
                return None, str(data.get("error") or data.get("message") or "invalid /api/me response")
            return None, "invalid /api/me response"
        except Exception as exc:
            return None, f"check_me exception: {exc}"

    def _get_challenge(self, session: curl_requests.Session, tier: int, hps: int) -> tuple[dict | None, str]:
        """Get PoW challenge."""
        print(f"  {self.account_name}: getting challenge tier={tier}, hps={hps:,} ...")
        try:
            resp = session.get(
                f"{BASE_URL}/api/pow/challenge",
                params={"tier": tier, "hps": hps},
                timeout=30,
            )
            data = response_resolve(resp, "get_challenge", self.account_name)
            if data and "challenge" in data:
                print(f"  {self.account_name}: challenge id={data.get('challengeId')}, difficulty={data.get('difficulty')}")
                return data, ""
            if isinstance(data, dict):
                return None, str(data.get("error") or data.get("message") or "invalid challenge response")
            return None, "invalid challenge response"
        except Exception as exc:
            return None, f"challenge exception: {exc}"

    def _submit(
        self,
        session: curl_requests.Session,
        challenge_id: str,
        nonce: int,
        tier: int,
    ) -> tuple[dict | None, str]:
        """Submit PoW solution."""
        print(f"  {self.account_name}: submitting check-in ...")
        try:
            resp = session.post(
                f"{BASE_URL}/api/pow/submit",
                json={"challengeId": challenge_id, "nonce": nonce, "tier": tier},
                timeout=30,
            )
            data = response_resolve(resp, "submit_checkin", self.account_name)
            if data and "rewardFinal" in data:
                print(f"  {self.account_name}: check-in success reward={data.get('rewardFinal')}")
                return data, ""
            if isinstance(data, dict):
                return None, str(data.get("error") or data.get("message") or "invalid submit response")
            return None, "invalid submit response"
        except Exception as exc:
            return None, f"submit exception: {exc}"

    async def _execute_with_sid(self, sid: str, tier: int, auth_source: str) -> tuple[bool, dict]:
        """Run check-in flow using sid."""
        cf_cookies, browser_headers = await self._get_cf_clearance()
        session = self._build_session(sid, cf_cookies, browser_headers)

        try:
            me_data, me_err = self._check_me(session)
            if not me_data:
                return False, {"error": f"/api/me failed ({me_err})", "auth_source": auth_source}

            if me_data.get("signedInToday"):
                today = me_data.get("todaySignin", {}) or {}
                return True, {
                    "reward_final": today.get("reward_final", today.get("rewardFinal", "0")),
                    "tier_name": today.get("tier_name", today.get("tierName", "")),
                    "already_signed": True,
                    "auth_source": auth_source,
                }

            hps = benchmark_hps()
            challenge_data, challenge_err = self._get_challenge(session, tier, hps)
            if not challenge_data:
                return False, {"error": f"get challenge failed ({challenge_err})", "auth_source": auth_source}

            result = calculate_nonce(challenge_data["challenge"], challenge_data["difficulty"])
            submit_data, submit_err = self._submit(session, challenge_data["challengeId"], result["nonce"], tier)
            if not submit_data:
                return False, {"error": f"submit failed ({submit_err})", "auth_source": auth_source}

            return True, {
                "reward_final": submit_data.get("rewardFinal", "0"),
                "reward_base": submit_data.get("rewardBase", "0"),
                "multiplier": submit_data.get("multiplier", "1"),
                "tier_name": submit_data.get("tierName", ""),
                "notes": submit_data.get("notes", ""),
                "pow_elapsed": result["elapsed"],
                "pow_hps": result["hps"],
                "already_signed": False,
                "auth_source": auth_source,
            }
        finally:
            session.close()

    async def _extract_sid_from_context(self, context) -> str:
        try:
            cookies = await context.cookies([BASE_URL])
            for item in cookies:
                if item.get("name") == "sid" and item.get("value"):
                    return str(item["value"])
        except Exception:
            pass
        return ""

    async def _is_qaq_logged_in(self, page) -> bool:
        try:
            ok = await page.evaluate(
                """async () => {
                    const resp = await fetch('/api/me', { credentials: 'include' });
                    if (!resp.ok) return false;
                    const data = await resp.json().catch(() => null);
                    return !!(data && data.user);
                }"""
            )
            return bool(ok)
        except Exception:
            return False

    async def _is_cf_challenge_page(self, page) -> bool:
        try:
            url = page.url.lower()
            if "__cf_chl_rt_tk" in url or "linux.do/challenge" in url:
                return True
            title = (await page.title()).lower()
            if "just a moment" in title or "attention required" in title:
                return True
            content = (await page.content()).lower()
            return "checking your browser before accessing" in content
        except Exception:
            return False

    async def _solve_cf_interstitial(self, page) -> bool:
        try:
            async with ClickSolver(
                framework=FrameworkType.CAMOUFOX,
                page=page,
                max_attempts=3,
                attempt_delay=3,
            ) as solver:
                await solver.solve_captcha(
                    captcha_container=page,
                    captcha_type=CaptchaType.CLOUDFLARE_INTERSTITIAL,
                )
            await page.wait_for_timeout(2500)
            return True
        except Exception:
            return False

    async def _click_first(self, page, selectors: list[str]) -> tuple[bool, str]:
        for selector in selectors:
            try:
                locator = page.locator(selector)
                if await locator.count() == 0:
                    continue
                await locator.first.click(timeout=5000)
                return True, selector
            except Exception:
                continue
        return False, ""

    async def _open_linuxdo_auth_entry(self, page) -> tuple[bool, str]:
        entry_urls = [
            f"{BASE_URL}/auth/login",
            f"{BASE_URL}/login",
            f"{BASE_URL}/",
        ]
        for entry_url in entry_urls:
            try:
                await page.goto(entry_url, wait_until="domcontentloaded")
                await page.wait_for_timeout(1200)
            except Exception:
                continue

            current_url = page.url.lower()
            if "connect.linux.do" in current_url or "/oauth2/authorize" in current_url:
                return True, f"direct:{entry_url}"

            clicked, used_selector = await self._click_first(page, LOGIN_BUTTON_SELECTORS)
            if clicked:
                await page.wait_for_timeout(800)
                return True, used_selector

        return False, ""

    async def _login_and_get_sid(self, credential: LinuxDoCredential) -> tuple[str, str]:
        """Login via LinuxDo in browser and return sid (with cache restore/save)."""
        username_hash = hashlib.sha256(credential.username.encode("utf-8")).hexdigest()[:8]
        cache_file_path = os.path.join(self.storage_state_dir, f"qaq_al_{username_hash}_storage_state.json")
        storage_state = cache_file_path if os.path.exists(cache_file_path) else None

        print(f"  {self.account_name}: trying LinuxDo login (cache={'hit' if storage_state else 'miss'})")

        async with AsyncCamoufox(
            headless=not self.debug,
            humanize=True,
            locale="en-US",
            geoip=True if self.camoufox_proxy_config else False,
            proxy=self.camoufox_proxy_config,
            os="macos",
            config={"forceScopeAccess": True},
        ) as browser:
            context = await browser.new_context(storage_state=storage_state)
            page = await context.new_page()

            try:
                # First attempt: restore from cache.
                await page.goto(f"{BASE_URL}/app", wait_until="domcontentloaded")
                await page.wait_for_timeout(1200)
                sid = await self._extract_sid_from_context(context)
                if sid and await self._is_qaq_logged_in(page):
                    await context.storage_state(path=cache_file_path)
                    return sid, "session restored from cache"

                # Need fresh LinuxDo login.
                clicked, used_selector = await self._open_linuxdo_auth_entry(page)
                if not clicked:
                    return "", f"linuxdo auth entry not found on qaq page (url={page.url})"

                login_submitted = False
                approve_clicked = False

                for _ in range(160):
                    sid = await self._extract_sid_from_context(context)
                    if sid and await self._is_qaq_logged_in(page):
                        await context.storage_state(path=cache_file_path)
                        state = "logged in via LinuxDo"
                        if login_submitted:
                            state += " (credential flow)"
                        if approve_clicked:
                            state += " (oauth approved)"
                        state += f", trigger={used_selector}"
                        return sid, state

                    if await self._is_cf_challenge_page(page):
                        await self._solve_cf_interstitial(page)
                        await page.wait_for_timeout(1200)
                        continue

                    url = page.url.lower()
                    if "linux.do/login" in url and not login_submitted:
                        try:
                            await page.fill("#login-account-name", credential.username)
                            await page.fill("#login-account-password", credential.password)
                            await page.click("#login-button")
                            login_submitted = True
                        except Exception:
                            pass

                    if "connect.linux.do" in url:
                        try:
                            approve = page.locator(APPROVE_BUTTON_SELECTOR).first
                            if await approve.count() > 0:
                                await approve.click(timeout=4000)
                                approve_clicked = True
                        except Exception:
                            pass

                    await page.wait_for_timeout(1200)

                return "", f"linuxdo login timeout (url={page.url})"
            finally:
                await page.close()
                await context.close()

    async def execute(
        self,
        sid: str | None = None,
        tier: int = 4,
        credential: LinuxDoCredential | None = None,
    ) -> tuple[bool, dict]:
        """
        Execute complete check-in flow.

        Args:
            sid: Existing sid cookie value (optional).
            tier: Difficulty tier.
            credential: LinuxDo credential, used as primary auth.
        """
        print(f"\n🚀 start account {self.account_name}")
        errors: list[str] = []
        cache_key = self._build_sid_cache_key(credential)
        cached_sid = self._read_cached_sid(cache_key)
        sid_fallback = str(sid or "").strip() or cached_sid

        if credential:
            refreshed_sid, login_msg = await self._login_and_get_sid(credential)
            if refreshed_sid:
                ok, result = await self._execute_with_sid(refreshed_sid, tier, auth_source="linuxdo")
                if ok:
                    result["sid_refreshed"] = (not sid) or (sid != refreshed_sid)
                    result["login_message"] = login_msg
                    self._save_cached_sid(cache_key, refreshed_sid)
                    return True, result
                errors.append(f"linuxdo auth failed: {result.get('error', 'unknown')}")
            else:
                errors.append(f"linuxdo login failed: {login_msg}")
        else:
            errors.append("linuxdo credential missing")

        if sid_fallback:
            auth_source = "sid_fallback" if sid else "sid_cache_fallback"
            ok, result = await self._execute_with_sid(sid_fallback, tier, auth_source=auth_source)
            if ok:
                self._save_cached_sid(cache_key, sid_fallback)
                return True, result
            errors.append(f"{auth_source} failed: {result.get('error', 'unknown')}")
        else:
            errors.append("sid missing")

        return False, {"error": " | ".join(errors)}
