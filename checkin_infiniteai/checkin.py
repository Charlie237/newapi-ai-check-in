#!/usr/bin/env python3
"""
Standalone infiniteai.cc check-in runner.
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from urllib.parse import urlparse

from camoufox.async_api import AsyncCamoufox
from playwright_captcha import CaptchaType, ClickSolver, FrameworkType

from utils.browser_utils import take_screenshot

BASE_URL = "https://infiniteai.cc"
CHECKIN_URL = f"{BASE_URL}/checkin"
LOGIN_URL = f"{BASE_URL}/login?next=%2Fcheckin"

LOGIN_USERNAME_SELECTORS = [
    "input[name='username']",
    "input[autocomplete='username']",
    "input[placeholder='用户名']",
    "input[placeholder='Username']",
    "input[type='text']",
]
LOGIN_PASSWORD_SELECTORS = [
    "input[name='password']",
    "input[autocomplete='current-password']",
    "input[placeholder='密码']",
    "input[placeholder='Password']",
    "input[type='password']",
]
LOGIN_SUBMIT_SELECTORS = [
    "button:has-text('登录')",
    "button:has-text('Sign in')",
    "button[type='submit']",
]
LINUXDO_ENTRY_SELECTORS = [
    "a[href*='/api/admin/login/linuxdo']",
    "button:has-text('使用 Linux.do 登录')",
    "a:has-text('使用 Linux.do 登录')",
    "button:has-text('LinuxDo')",
    "a:has-text('LinuxDo')",
]
CHECKIN_BUTTON_SELECTORS = [
    "button:has-text('立即签到')",
    "button:has-text('Check in now')",
    "button:has-text('签到')",
    "[role='button']:has-text('立即签到')",
    "[role='button']:has-text('Check in now')",
    "[role='button']:has-text('签到')",
]
FEEDBACK_SELECTORS = [
    ".el-message__content",
    ".ant-message-notice-content",
    ".toast",
    ".van-toast__text",
    "[role='alert']",
]
APPROVE_BUTTON_SELECTOR = "a[href^='/oauth2/approve']"
CHECKIN_API_CANDIDATES = [
    "/api/admin/checkin",
    "/api/checkin",
    "/api/admin/check-in",
    "/api/admin/checkin/claim",
    "/api/admin/daily-checkin",
    "/api/admin/daily-checkin/claim",
]
ALREADY_HINTS = [
    "今日已签到",
    "已经签到",
    "你今天已经签到过了",
    "already checked in today",
    "already claimed",
    "claimed today",
]
SUCCESS_HINTS = [
    "签到成功",
    "领取成功",
    "check-in successful",
    "check in successful",
    "claim success",
]
FAIL_HINTS = [
    "签到失败",
    "登录失败",
    "invalid password",
    "密码错误",
    "failed",
    "error",
]
LOGIN_REQUIRED_HINTS = [
    "你需要先登录才能继续",
    "管理员登录",
    "admin login",
    "sign in to continue",
    "使用 linux.do 登录",
    "linux.do 登录",
]
AUTH_PAGE_HINTS = [
    "立即签到",
    "今日已签到",
    "签到日历",
    "奖励范围",
    "check in now",
    "already checked in today",
    "check-in calendar",
    "reward range",
]


@dataclass
class UserCredential:
    username: str
    password: str


@dataclass
class LinuxDoCredential:
    username: str
    password: str


class InfiniteAICheckIn:
    def __init__(
        self,
        account_name: str,
        cookies: dict | None = None,
        user_credential: UserCredential | None = None,
        linuxdo_credential: LinuxDoCredential | None = None,
        proxy: dict | None = None,
        storage_state_dir: str = "storage-states",
        debug: bool = False,
    ):
        self.account_name = account_name
        self.cookies = cookies or {}
        self.user_credential = user_credential
        self.linuxdo_credential = linuxdo_credential
        self.proxy = proxy
        self.storage_state_dir = storage_state_dir
        self.debug = debug
        self.auth_source = "infiniteai"
        os.makedirs(self.storage_state_dir, exist_ok=True)

    def _storage_state_path(self) -> str:
        seed = self.account_name
        if self.user_credential and self.user_credential.username:
            seed = f"user:{self.user_credential.username}"
        elif self.linuxdo_credential and self.linuxdo_credential.username:
            seed = f"linuxdo:{self.linuxdo_credential.username}"
        name_hash = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:8]
        return os.path.join(self.storage_state_dir, f"infiniteai_{name_hash}_storage_state.json")

    @staticmethod
    def _build_browser_cookies(base_url: str, cookies: dict) -> list[dict]:
        if not cookies:
            return []
        domain = urlparse(base_url).netloc
        rows: list[dict] = []
        for name, value in cookies.items():
            if not name or value is None:
                continue
            rows.append(
                {
                    "name": str(name),
                    "value": str(value),
                    "domain": domain,
                    "path": "/",
                    "secure": True,
                    "httpOnly": False,
                    "sameSite": "Lax",
                }
            )
        return rows

    @staticmethod
    def _text_has_any(text: str, hints: list[str]) -> bool:
        raw = (text or "").strip().lower()
        return bool(raw and any(h.lower() in raw for h in hints))

    @staticmethod
    def _parse_number(value) -> float | None:
        if isinstance(value, bool):
            return None
        if isinstance(value, (int, float)):
            return float(value)
        if isinstance(value, str):
            text = value.strip().replace(",", "")
            if text and re.fullmatch(r"[-+]?\d+(?:\.\d+)?", text):
                try:
                    return float(text)
                except ValueError:
                    return None
        return None

    @staticmethod
    def _iter_mappings(payload):
        if isinstance(payload, dict):
            yield payload
            for v in payload.values():
                yield from InfiniteAICheckIn._iter_mappings(v)
        elif isinstance(payload, list):
            for v in payload:
                yield from InfiniteAICheckIn._iter_mappings(v)

    def _extract_by_hints(self, payload: dict, hints: tuple[str, ...]) -> float | None:
        for mapping in self._iter_mappings(payload):
            for key, value in mapping.items():
                key_text = str(key).strip().lower()
                if any(h in key_text for h in hints):
                    parsed = self._parse_number(value)
                    if parsed is not None:
                        return parsed
        return None

    async def _fetch_json(self, page, path: str, method: str = "GET", body: dict | None = None) -> dict:
        return await page.evaluate(
            """async ({ path, method, body }) => {
                const init = { method, credentials: "include" };
                if (body !== null) {
                    init.headers = { "content-type": "application/json" };
                    init.body = JSON.stringify(body);
                }
                const resp = await fetch(path, init);
                const text = await resp.text();
                let json = null;
                try { json = JSON.parse(text); } catch (e) {}
                return { ok: resp.ok, status: resp.status, json, text };
            }""",
            {"path": path, "method": method, "body": body},
        )

    async def _is_logged_in(self, page) -> bool:
        try:
            resp = await self._fetch_json(page, "/api/admin/session")
            payload = resp.get("json")
            if resp.get("status") == 200 and isinstance(payload, dict):
                for mapping in self._iter_mappings(payload):
                    if mapping.get("authenticated") is True or mapping.get("loggedIn") is True:
                        return True
                    if isinstance(mapping.get("user"), dict):
                        return True
                    if mapping.get("error"):
                        continue
                    username = str(mapping.get("username") or "").strip()
                    email = str(mapping.get("email") or "").strip()
                    user_id = mapping.get("userId", mapping.get("id"))
                    if username or email:
                        return True
                    if isinstance(user_id, int) and user_id > 0:
                        return True
                    if mapping.get("success") is True and mapping.get("data") not in (None, "", [], {}):
                        return True

                msg = str(payload.get("message") or payload.get("error") or resp.get("text") or "").lower()
                if self._text_has_any(msg, LOGIN_REQUIRED_HINTS):
                    return False
        except Exception:
            pass

        try:
            content = await page.evaluate("""() => (document.body?.innerText || "").replace(/\\s+/g, " ").slice(0, 4000)""")
            if self._text_has_any(content, AUTH_PAGE_HINTS):
                return True
            if self._text_has_any(content, LOGIN_REQUIRED_HINTS):
                return False
        except Exception:
            pass

        try:
            cookies = await page.context.cookies([BASE_URL])
            for item in cookies:
                name = str(item.get("name") or "").strip().lower()
                value = str(item.get("value") or "").strip()
                if not name or not value:
                    continue
                if name in {"session", "sid", "next-auth.session-token", "__secure-next-auth.session-token"}:
                    return True
                if ("session" in name or "auth" in name) and len(value) > 16:
                    return True
        except Exception:
            pass

        return False

    async def _extract_feedback_text(self, page) -> str:
        for selector in FEEDBACK_SELECTORS:
            try:
                locator = page.locator(selector).first
                if await locator.count() == 0:
                    continue
                text = (await locator.inner_text(timeout=600)).strip()
                if text:
                    return text
            except Exception:
                continue
        return ""

    async def _click_first(self, page, selectors: list[str]) -> tuple[bool, str]:
        for selector in selectors:
            try:
                locator = page.locator(selector)
                count = await locator.count()
                if count == 0:
                    continue
                for idx in range(count):
                    node = locator.nth(idx)
                    try:
                        if await node.is_visible(timeout=400):
                            await node.click(timeout=5000)
                            return True, selector
                    except Exception:
                        continue
                await locator.first.click(timeout=3500)
                return True, selector
            except Exception:
                continue
        return False, ""

    async def _pick_visible_field(self, page, selectors: list[str]):
        for selector in selectors:
            try:
                locator = page.locator(selector)
                count = await locator.count()
                if count == 0:
                    continue
                for idx in range(min(count, 4)):
                    node = locator.nth(idx)
                    try:
                        if await node.is_visible(timeout=400):
                            return node
                    except Exception:
                        continue
            except Exception:
                continue
        return None

    async def _is_cf_challenge_page(self, page) -> bool:
        try:
            url = page.url.lower()
            if any(token in url for token in ("__cf_chl_rt_tk", "__cf_chl_", "/cdn-cgi/challenge")):
                return True
            if "linux.do/login" in url:
                return False
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
                await solver.solve_captcha(captcha_container=page, captcha_type=CaptchaType.CLOUDFLARE_INTERSTITIAL)
            await page.wait_for_timeout(2000)
            return True
        except Exception:
            return False

    async def _submit_user_login(self, page) -> tuple[bool, str]:
        if not self.user_credential:
            return False, "missing user credential"
        user_field = await self._pick_visible_field(page, LOGIN_USERNAME_SELECTORS)
        pass_field = await self._pick_visible_field(page, LOGIN_PASSWORD_SELECTORS)
        if user_field is None or pass_field is None:
            return False, "username/password field not found"
        try:
            await user_field.fill(self.user_credential.username)
            await pass_field.fill(self.user_credential.password)
        except Exception as exc:
            return False, f"fill failed: {exc}"
        clicked, selector = await self._click_first(page, LOGIN_SUBMIT_SELECTORS)
        if clicked:
            return True, selector
        try:
            await pass_field.press("Enter")
            return True, "Enter"
        except Exception as exc:
            return False, f"submit failed: {exc}"

    async def _submit_linuxdo_login(self, page) -> tuple[bool, str]:
        if not self.linuxdo_credential:
            return False, "missing linuxdo credential"
        fields = [
            ("#login-account-name", "#login-account-password", "#login-button"),
            ("#signin_username", "#signin_password", "#signin-button"),
            ("input[name='username']", "input[name='password']", "#signin-button"),
            ("input[name='login']", "input[name='password']", "#login-button"),
        ]
        for username_selector, password_selector, submit_selector in fields:
            try:
                user_locator = page.locator(username_selector)
                pass_locator = page.locator(password_selector)
                if await user_locator.count() == 0 or await pass_locator.count() == 0:
                    continue
                await user_locator.first.fill(self.linuxdo_credential.username)
                await pass_locator.first.fill(self.linuxdo_credential.password)
                submit_locator = page.locator(submit_selector)
                if await submit_locator.count() > 0:
                    await submit_locator.first.click(timeout=5000)
                else:
                    await pass_locator.first.press("Enter")
                return True, f"{username_selector}->{submit_selector}"
            except Exception:
                continue
        return False, "linuxdo form selectors not matched"

    async def _login_via_user(self, page) -> tuple[bool, str]:
        if not self.user_credential:
            return False, "user credential not provided"
        await page.goto(LOGIN_URL, wait_until="domcontentloaded")
        await page.wait_for_timeout(1000)
        if await self._is_logged_in(page):
            self.auth_source = "storage-state"
            return True, "already logged in"
        submitted, submit_msg = await self._submit_user_login(page)
        if not submitted:
            return False, submit_msg
        for _ in range(70):
            if await self._is_logged_in(page):
                self.auth_source = "user"
                return True, f"user login success ({submit_msg})"
            feedback = await self._extract_feedback_text(page)
            if feedback and self._text_has_any(feedback, FAIL_HINTS) and not self._text_has_any(feedback, ALREADY_HINTS):
                return False, f"user login rejected: {feedback}"
            if await self._is_cf_challenge_page(page):
                await self._solve_cf_interstitial(page)
            await page.wait_for_timeout(1000)
        return False, f"user login timeout (url={page.url})"

    async def _login_via_linuxdo(self, page) -> tuple[bool, str]:
        if not self.linuxdo_credential:
            return False, "linuxdo credential not provided"
        await page.goto(LOGIN_URL, wait_until="domcontentloaded")
        await page.wait_for_timeout(1000)
        clicked, trigger = await self._click_first(page, LINUXDO_ENTRY_SELECTORS)
        if not clicked:
            trigger = "direct"
            try:
                await page.goto(f"{BASE_URL}/api/admin/login/linuxdo?next=%2Fcheckin", wait_until="domcontentloaded")
            except Exception:
                return False, "linuxdo auth entry not found"
        login_submitted = False
        submit_attempts = 0
        approve_attempts = 0
        last_submit_loop = -999
        last_feedback = ""
        for loop_idx in range(220):
            if await self._is_logged_in(page):
                self.auth_source = "linux.do"
                return True, f"linuxdo login success (trigger={trigger})"

            feedback = await self._extract_feedback_text(page)
            if feedback:
                last_feedback = feedback

            if await self._is_cf_challenge_page(page):
                await self._solve_cf_interstitial(page)
                await page.wait_for_timeout(1200)
                continue
            url = page.url.lower()
            if loop_idx in {10, 40, 80, 120, 160} and "/login" in url and "linux.do" not in url:
                try:
                    await page.goto(f"{BASE_URL}/api/admin/login/linuxdo?next=%2Fcheckin", wait_until="domcontentloaded")
                    await page.wait_for_timeout(1000)
                    continue
                except Exception:
                    pass
            if "linux.do/login" in url and ((not login_submitted) or (loop_idx - last_submit_loop) >= 35):
                ok, submit_msg = await self._submit_linuxdo_login(page)
                if ok:
                    login_submitted = True
                    submit_attempts += 1
                    last_submit_loop = loop_idx
                    last_feedback = submit_msg
            if "connect.linux.do" in url:
                try:
                    approve = page.locator(APPROVE_BUTTON_SELECTOR).first
                    if await approve.count() > 0:
                        await approve.click(timeout=4000)
                        approve_attempts += 1
                except Exception:
                    pass
            await page.wait_for_timeout(1200)
        return (
            False,
            "linuxdo login timeout "
            f"(url={page.url}, submitted={login_submitted}, submit_attempts={submit_attempts}, "
            f"approve_attempts={approve_attempts}, feedback={last_feedback[:80]})",
        )

    async def _is_already_by_ui(self, page) -> bool:
        try:
            content = await page.evaluate("""() => (document.body?.innerText || "").replace(/\\s+/g, " ").slice(0, 3000)""")
        except Exception:
            return False
        return self._text_has_any(content, ALREADY_HINTS)

    def _parse_checkin_api_response(self, result: dict, api_path: str) -> tuple[bool, dict]:
        status = int(result.get("status") or 0)
        payload = result.get("json") if isinstance(result.get("json"), dict) else {}
        text = str(payload.get("message") or payload.get("msg") or payload.get("error") or result.get("text") or "")[:200]
        already = self._text_has_any(text, ALREADY_HINTS)
        reward = self._extract_by_hints(payload, ("reward", "amount", "gain", "bonus"))
        if status in {200, 201}:
            if payload.get("success") is False and not already:
                return False, {"error": text or f"{api_path} rejected", "api": api_path, "status": status}
            return True, {"already": already, "message": text or "checkin completed", "reward": reward, "api": api_path}
        if status in {400, 409} and already:
            return True, {"already": True, "message": text or "already checked in today", "api": api_path}
        return False, {"error": text or f"{api_path} http={status}", "api": api_path, "status": status}

    async def _try_api_checkin(self, page) -> tuple[bool, dict]:
        last_error = {"error": "no api candidate matched"}
        for api_path in CHECKIN_API_CANDIDATES:
            try:
                result = await self._fetch_json(page, api_path, method="POST")
                ok, parsed = self._parse_checkin_api_response(result, api_path)
                if ok:
                    return True, parsed
                last_error = parsed
            except Exception as exc:
                last_error = {"error": f"{api_path} exception: {exc}"}
        return False, last_error

    async def _collect_session_snapshot(self, page) -> dict:
        resp = await self._fetch_json(page, "/api/admin/session")
        payload = resp.get("json") if isinstance(resp.get("json"), dict) else {}
        return {
            "balance": self._extract_by_hints(payload, ("balance", "credit", "quota", "remaining")),
            "total_claims": self._extract_by_hints(payload, ("totalclaim", "checkincount", "signincount", "totalcheck")),
            "reward_min": self._extract_by_hints(payload, ("rewardmin", "checkinrewardmin")),
            "reward_max": self._extract_by_hints(payload, ("rewardmax", "checkinrewardmax")),
        }

    async def _run_checkin(self, page) -> tuple[bool, dict]:
        await page.goto(CHECKIN_URL, wait_until="domcontentloaded")
        await page.wait_for_timeout(1200)
        if not await self._is_logged_in(page):
            return False, {"error": "not logged in at /checkin"}
        if await self._is_already_by_ui(page):
            return True, {"already": True, "message": "already checked in today (ui)"}
        clicked, selector = await self._click_first(page, CHECKIN_BUTTON_SELECTORS)
        if not clicked:
            api_ok, api_result = await self._try_api_checkin(page)
            if api_ok:
                return True, api_result
            await take_screenshot(page, "infiniteai_checkin_button_not_found", self.account_name)
            return False, {"error": f"checkin button not found ({api_result.get('error', 'unknown')})"}
        await page.wait_for_timeout(1200)
        fail_text = ""
        for _ in range(20):
            feedback = await self._extract_feedback_text(page)
            if feedback:
                if self._text_has_any(feedback, ALREADY_HINTS):
                    return True, {"already": True, "message": feedback, "selector": selector}
                if self._text_has_any(feedback, SUCCESS_HINTS):
                    return True, {"already": False, "message": feedback, "selector": selector}
                if self._text_has_any(feedback, FAIL_HINTS):
                    fail_text = feedback
            if await self._is_already_by_ui(page):
                return True, {"already": True, "message": "already checked by state after click", "selector": selector}
            await page.wait_for_timeout(900)
        api_ok, api_result = await self._try_api_checkin(page)
        if api_ok:
            api_result.setdefault("selector", selector)
            return True, api_result
        await take_screenshot(page, "infiniteai_checkin_unconfirmed", self.account_name)
        return False, {"error": f"checkin not confirmed ({fail_text or api_result.get('error', 'no feedback')})"}

    async def execute(self) -> tuple[bool, dict]:
        print(f"Starting infiniteai flow for {self.account_name}")
        details: list[str] = []
        storage_state_path = self._storage_state_path()
        storage_state = storage_state_path if os.path.exists(storage_state_path) else None
        browser_cookies = self._build_browser_cookies(BASE_URL, self.cookies)

        async with AsyncCamoufox(
            headless=not self.debug,
            humanize=True,
            locale="en-US",
            geoip=True if self.proxy else False,
            proxy=self.proxy,
            os="macos",
            config={"forceScopeAccess": True},
        ) as browser:
            details.append(f"[cache] storage-state {'hit' if storage_state else 'miss'}")
            if storage_state:
                try:
                    context = await browser.new_context(storage_state=storage_state)
                except Exception as exc:
                    details.append(f"[cache] restore failed: {exc}")
                    context = await browser.new_context()
            else:
                context = await browser.new_context()

            page = await context.new_page()
            try:
                if browser_cookies:
                    await context.add_cookies(browser_cookies)
                    details.append(f"[cookie] loaded {len(browser_cookies)} cookies")

                await page.goto(CHECKIN_URL, wait_until="domcontentloaded")
                await page.wait_for_timeout(1200)
                logged_in = await self._is_logged_in(page)

                if logged_in:
                    if storage_state and not browser_cookies:
                        details.append("[login] session restored from storage-state cache")
                        self.auth_source = "storage-state"
                    elif browser_cookies:
                        details.append("[login] session restored from cookies")
                        self.auth_source = "cookies"
                    else:
                        details.append("[login] session already active")
                    try:
                        await context.storage_state(path=storage_state_path)
                        details.append("[cache] storage-state saved")
                    except Exception as exc:
                        details.append(f"[cache] save failed: {exc}")
                else:
                    user_ok, user_msg = await self._login_via_user(page)
                    details.append(f"[login-user] {user_msg}")
                    if not user_ok:
                        linuxdo_ok, linuxdo_msg = await self._login_via_linuxdo(page)
                        details.append(f"[login-linuxdo] {linuxdo_msg}")
                        if not linuxdo_ok:
                            return False, {
                                "error": f"login failed: user={user_msg}; linuxdo={linuxdo_msg}",
                                "details": details,
                                "auth_source": self.auth_source,
                            }
                    try:
                        await context.storage_state(path=storage_state_path)
                        details.append("[cache] storage-state saved")
                    except Exception as exc:
                        details.append(f"[cache] save failed: {exc}")

                checkin_ok, checkin_result = await self._run_checkin(page)
                details.append(f"[checkin] {checkin_result}")
                if not checkin_ok:
                    return False, {
                        "error": "checkin failed",
                        "details": details,
                        "checkin_result": checkin_result,
                        "auth_source": self.auth_source,
                    }

                snapshot = await self._collect_session_snapshot(page)
                return True, {
                    "display": "infiniteai done",
                    "details": details,
                    "checkin_result": checkin_result,
                    "session_snapshot": snapshot,
                    "auth_source": self.auth_source,
                }
            except Exception as exc:
                await take_screenshot(page, "infiniteai_execute_exception", self.account_name)
                return False, {"error": f"runtime exception: {exc}", "details": details, "auth_source": self.auth_source}
            finally:
                await page.close()
                await context.close()
