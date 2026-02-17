#!/usr/bin/env python3
"""
Standalone hybgzs check-in runner.

Flow:
1) Restore session from cookies (if provided) or login with LinuxDo credentials.
2) Open daily check-in page and click check-in button.
3) Solve Turnstile if required.
4) Call wheel API to consume remaining spins.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import urlparse

from camoufox.async_api import AsyncCamoufox
from playwright_captcha import CaptchaType, ClickSolver, FrameworkType

from utils.browser_utils import take_screenshot

BASE_URL = "https://cdk.hybgzs.com"

CHECKIN_BUTTON_SELECTORS = [
    "button:has-text('\u7acb\u5373\u7b7e\u5230')",
    "[role='button']:has-text('\u7acb\u5373\u7b7e\u5230')",
    "button:has-text('\u7b7e\u5230')",
    "[role='button']:has-text('\u7b7e\u5230')",
]

LOGIN_BUTTON_SELECTORS = [
    "button:has-text('LinuxDo')",
    "button:has-text('LINUX DO')",
    "a:has-text('LinuxDo')",
    "a:has-text('LINUX DO')",
]

FEEDBACK_SELECTORS = [
    ".el-message__content",
    ".ant-message-notice-content",
    ".toast",
    ".van-toast__text",
    "[role='alert']",
]

ANNOUNCEMENT_CLOSE_SELECTORS = [
    "button:has-text('\u6211\u77e5\u9053\u4e86')",
    "button:has-text('\u77e5\u9053\u4e86')",
    "button:has-text('\u5173\u95ed')",
    "[role='dialog'] button:has-text('\u6211\u77e5\u9053\u4e86')",
]

TURNSTILE_MODAL_TEXTS = [
    "\u5b8c\u6210\u9a8c\u8bc1\u540e\u81ea\u52a8\u7b7e\u5230",
    "\u4f60\u662f\u771f\u7684\u4eba\u7c7b\u5417",
    "verify you are human",
]


@dataclass
class LinuxDoCredential:
    username: str
    password: str


class HybgzsCheckIn:
    def __init__(
        self,
        account_name: str,
        cookies: dict | None = None,
        credential: LinuxDoCredential | None = None,
        proxy: dict | None = None,
        run_wheel: bool = True,
        max_wheel_spins: int = 5,
        storage_state_dir: str = "storage-states",
        debug: bool = False,
    ):
        self.account_name = account_name
        self.cookies = cookies or {}
        self.credential = credential
        self.proxy = proxy
        self.run_wheel = run_wheel
        self.max_wheel_spins = max(0, int(max_wheel_spins))
        self.storage_state_dir = storage_state_dir
        self.debug = debug
        self._click_solver: ClickSolver | None = None
        self._solver_prepared = False
        os.makedirs(self.storage_state_dir, exist_ok=True)

    def _debug_log(self, message: str) -> None:
        if self.debug:
            print(f"[hybgzs:{self.account_name}] {message}")

    def _storage_state_path(self) -> str | None:
        if not self.credential or not self.credential.username:
            return None
        username_hash = hashlib.sha256(self.credential.username.encode("utf-8")).hexdigest()[:8]
        return os.path.join(self.storage_state_dir, f"hybgzs_{username_hash}_storage_state.json")

    @staticmethod
    def _build_browser_cookies(base_url: str, cookies: dict) -> list[dict]:
        if not cookies:
            return []
        domain = urlparse(base_url).netloc
        result = []
        for name, value in cookies.items():
            if not name or value is None:
                continue
            result.append(
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
        return result

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
            data = await self._fetch_json(page, "/api/auth/session")
            if data.get("status") != 200:
                return False
            session = data.get("json") or {}
            return bool(isinstance(session, dict) and session.get("user"))
        except Exception:
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
                    candidate = locator.nth(idx)
                    try:
                        if not await candidate.is_visible(timeout=400):
                            continue
                        await candidate.click(timeout=5000)
                        return True, selector
                    except Exception:
                        continue
                # Fall back to first match when visibility probing is unreliable.
                await locator.first.click(timeout=3500)
                return True, selector
            except Exception:
                continue
        return False, ""

    async def _dismiss_blocking_modal(self, page) -> bool:
        clicked = False
        for _ in range(3):
            ok, _ = await self._click_first(page, ANNOUNCEMENT_CLOSE_SELECTORS)
            if not ok:
                break
            clicked = True
            await page.wait_for_timeout(600)
        return clicked

    async def _is_cf_challenge_page(self, page) -> bool:
        try:
            url = page.url.lower()
            if "__cf_chl_rt_tk" in url or "linux.do/challenge" in url:
                return True
            title = (await page.title()).lower()
            if "just a moment" in title:
                return True
            content = (await page.content()).lower()
            if "checking your browser before accessing" in content:
                return True
            if "attention required!" in title:
                return True
            return False
        except Exception:
            return False

    @staticmethod
    def _text_contains_turnstile_hint(text: str) -> bool:
        text = (text or "").lower()
        if not text:
            return False
        hints = [
            "\u4eba\u673a\u9a8c\u8bc1",
            "\u9a8c\u8bc1",
            "verify you are human",
            "turnstile",
            "captcha",
        ]
        return any(hint in text for hint in hints)

    async def _prepare_click_solver(self, page) -> bool:
        if self._solver_prepared and self._click_solver is not None:
            return True
        try:
            self._click_solver = ClickSolver(
                framework=FrameworkType.CAMOUFOX,
                page=page,
                max_attempts=4,
                attempt_delay=2,
            )
            # Must run before target pages load so unlockShadowRoot init script is effective.
            await self._click_solver.prepare()
            self._solver_prepared = True
            return True
        except Exception:
            self._click_solver = None
            self._solver_prepared = False
            return False

    async def _cleanup_click_solver(self) -> None:
        if self._click_solver is None:
            return
        try:
            await self._click_solver.cleanup()
        except Exception:
            pass
        finally:
            self._click_solver = None
            self._solver_prepared = False

    async def _is_turnstile_modal_visible(self, page) -> bool:
        for text in TURNSTILE_MODAL_TEXTS:
            try:
                locator = page.locator(f"text={text}").first
                if await locator.count() == 0:
                    continue
                if await locator.is_visible(timeout=400):
                    return True
            except Exception:
                continue
        return False

    async def _has_turnstile_markers(self, page) -> bool:
        try:
            return bool(
                await page.evaluate(
                    """() => {
                        const roots = [document];
                        const visited = new Set([document]);
                        let hasCfScript = false;
                        let hasCfInput = false;
                        let hasCfIframe = false;

                        while (roots.length) {
                            const root = roots.shift();
                            if (!root || !root.querySelectorAll) continue;

                            if (!hasCfScript && root.querySelector("script[src*='challenges.cloudflare.com/turnstile']")) {
                                hasCfScript = true;
                            }
                            if (!hasCfInput && root.querySelector("input[name='cf-turnstile-response'], textarea[name='cf-turnstile-response']")) {
                                hasCfInput = true;
                            }
                            if (!hasCfIframe) {
                                const iframes = Array.from(root.querySelectorAll("iframe"));
                                hasCfIframe = iframes.some((frame) => {
                                    const src = (frame.getAttribute("src") || "").toLowerCase();
                                    const title = (frame.getAttribute("title") || "").toLowerCase();
                                    return (
                                        src.includes("challenges.cloudflare.com") ||
                                        src.includes("turnstile") ||
                                        title.includes("cloudflare") ||
                                        title.includes("turnstile")
                                    );
                                });
                            }

                            const hosts = root.querySelectorAll("*");
                            for (const host of hosts) {
                                const shadow = host.shadowRoot;
                                if (shadow && !visited.has(shadow)) {
                                    visited.add(shadow);
                                    roots.push(shadow);
                                }
                            }
                        }

                        const text = (document.body?.innerText || "").toLowerCase();
                        const hasHumanText =
                            text.includes("verify you are human") ||
                            text.includes("人机验证") ||
                            text.includes("你是真的人类吗") ||
                            text.includes("完成验证后自动签到");
                        return hasCfScript || hasCfInput || hasCfIframe || hasHumanText;
                    }"""
                )
            )
        except Exception:
            return False

    async def _count_turnstile_iframes_deep(self, page) -> int:
        try:
            value = await page.evaluate(
                """() => {
                    const roots = [document];
                    const visited = new Set([document]);
                    let count = 0;

                    while (roots.length) {
                        const root = roots.shift();
                        if (!root || !root.querySelectorAll) continue;

                        const iframes = Array.from(root.querySelectorAll("iframe"));
                        for (const frame of iframes) {
                            const src = (frame.getAttribute("src") || "").toLowerCase();
                            const title = (frame.getAttribute("title") || "").toLowerCase();
                            if (
                                src.includes("challenges.cloudflare.com") ||
                                src.includes("turnstile") ||
                                title.includes("cloudflare") ||
                                title.includes("turnstile")
                            ) {
                                count += 1;
                            }
                        }

                        const hosts = root.querySelectorAll("*");
                        for (const host of hosts) {
                            const shadow = host.shadowRoot;
                            if (shadow && !visited.has(shadow)) {
                                visited.add(shadow);
                                roots.push(shadow);
                            }
                        }
                    }

                    return count;
                }"""
            )
            return int(value or 0)
        except Exception:
            return 0

    async def _collect_turnstile_click_points(self, page) -> list[dict]:
        try:
            points = await page.evaluate(
                """() => {
                    const points = [];
                    const pointKeys = new Set();
                    const roots = [document];
                    const visited = new Set([document]);
                    const patterns = [
                        /verify you are human/i,
                        /cloudflare/i,
                        /\\u4eba\\u673a\\u9a8c\\u8bc1/,
                        /\\u4f60\\u662f\\u771f\\u7684\\u4eba\\u7c7b\\u5417/,
                        /\\u5b8c\\u6210\\u9a8c\\u8bc1\\u540e\\u81ea\\u52a8\\u7b7e\\u5230/,
                        /\\u8ba9\\u6211\\u7528\\u9b54\\u6cd5\\u9a8c\\u8bc1\\u4e00\\u4e0b/,
                        /\\u8ba9\\u7528\\u9b54\\u6cd5\\u9a8c\\u8bc1\\u4e00\\u4e0b/,
                    ];

                    const isVisible = (el) => {
                        if (!el) return false;
                        const rect = el.getBoundingClientRect();
                        if (rect.width < 8 || rect.height < 8) return false;
                        if (rect.bottom <= 0 || rect.right <= 0) return false;
                        if (rect.top >= window.innerHeight || rect.left >= window.innerWidth) return false;
                        const style = window.getComputedStyle(el);
                        if (style.display === "none" || style.visibility === "hidden") return false;
                        if (Number(style.opacity || "1") <= 0.01) return false;
                        return true;
                    };

                    const addPoint = (x, y, label) => {
                        const xi = Math.round(x);
                        const yi = Math.round(y);
                        if (xi < 3 || yi < 3 || xi > window.innerWidth - 3 || yi > window.innerHeight - 3) return;
                        const key = `${xi}:${yi}`;
                        if (pointKeys.has(key)) return;
                        pointKeys.add(key);
                        points.push({ x: xi, y: yi, label });
                    };

                    while (roots.length) {
                        const root = roots.shift();
                        if (!root || !root.querySelectorAll) continue;

                        const iframes = Array.from(root.querySelectorAll("iframe"));
                        for (const frame of iframes) {
                            if (!isVisible(frame)) continue;
                            const src = (frame.getAttribute("src") || "").toLowerCase();
                            const title = (frame.getAttribute("title") || "").toLowerCase();
                            const isCf =
                                src.includes("challenges.cloudflare.com") ||
                                src.includes("turnstile") ||
                                title.includes("cloudflare") ||
                                title.includes("turnstile");
                            if (!isCf) continue;
                            const rect = frame.getBoundingClientRect();
                            addPoint(rect.left + Math.min(Math.max(rect.width * 0.16, 18), 36), rect.top + rect.height * 0.5, "iframe-left");
                            addPoint(rect.left + rect.width * 0.5, rect.top + rect.height * 0.5, "iframe-center");
                        }

                        const checkboxes = Array.from(root.querySelectorAll("[role='checkbox'], input[type='checkbox']"));
                        for (const box of checkboxes) {
                            if (!isVisible(box)) continue;
                            const rect = box.getBoundingClientRect();
                            addPoint(rect.left + rect.width * 0.5, rect.top + rect.height * 0.5, "checkbox");
                        }

                        const textNodes = Array.from(root.querySelectorAll("div, span, p, label, button, strong, small, h1, h2, h3"));
                        for (const el of textNodes) {
                            if (!isVisible(el)) continue;
                            const txt = (el.textContent || "").trim().toLowerCase();
                            if (!txt || !patterns.some((re) => re.test(txt))) continue;
                            const rect = el.getBoundingClientRect();
                            addPoint(rect.left + Math.min(Math.max(rect.width * 0.2, 30), 120), rect.top + rect.height * 0.5, "hint-left");
                            addPoint(rect.left + rect.width * 0.5, rect.top + rect.height * 0.5, "hint-center");
                        }

                        const dialogs = Array.from(root.querySelectorAll("[role='dialog'], .el-dialog, .ant-modal, .modal, .dialog"));
                        for (const dialog of dialogs) {
                            if (!isVisible(dialog)) continue;
                            const txt = (dialog.textContent || "").trim().toLowerCase();
                            if (!txt || !patterns.some((re) => re.test(txt))) continue;
                            const rect = dialog.getBoundingClientRect();
                            const xs = [0.16, 0.22, 0.28, 0.34];
                            const ys = [0.50, 0.56, 0.62, 0.68];
                            for (const rx of xs) {
                                for (const ry of ys) {
                                    addPoint(rect.left + rect.width * rx, rect.top + rect.height * ry, "dialog-heuristic");
                                }
                            }
                        }

                        const hosts = root.querySelectorAll("*");
                        for (const host of hosts) {
                            const shadow = host.shadowRoot;
                            if (shadow && !visited.has(shadow)) {
                                visited.add(shadow);
                                roots.push(shadow);
                            }
                        }
                    }

                    return points.slice(0, 80);
                }"""
            )
            if isinstance(points, list):
                return points
        except Exception:
            pass
        return []

    async def _click_turnstile_verify_fallback(self, page) -> bool:
        # Some pages render Turnstile without a discoverable iframe.
        # Try direct selectors first.
        direct_selectors = [
            "[role='checkbox']",
            "input[type='checkbox']",
            "iframe[src*='challenges.cloudflare.com']",
            "iframe[src*='turnstile']",
            "iframe[title*='Cloudflare']",
            "iframe[title*='turnstile']",
            "label:has-text('Verify you are human')",
            "div:has-text('Verify you are human')",
            "span:has-text('Verify you are human')",
            "text=Verify you are human",
            "text=verify you are human",
            "text=完成验证后自动签到",
            "text=你是真的人类吗",
            "text=让我用魔法验证一下",
        ]

        for selector in direct_selectors:
            try:
                locator = page.locator(selector).first
                if await locator.count() == 0:
                    continue
                if not await locator.is_visible(timeout=350):
                    continue
                await locator.click(timeout=1200)
                await page.wait_for_timeout(800)
                return True
            except Exception:
                continue

        points = await self._collect_turnstile_click_points(page)
        if not points:
            self._debug_log("turnstile fallback: no candidate click points")
            return False

        self._debug_log(f"turnstile fallback points={len(points)}")
        for idx, point in enumerate(points[:30]):
            try:
                x = float(point.get("x", 0))
                y = float(point.get("y", 0))
                if x < 3 or y < 3:
                    continue

                for dx, dy in ((0, 0), (-4, -2), (3, 2)):
                    tx = max(3, x + dx)
                    ty = max(3, y + dy)
                    await page.mouse.move(tx, ty, steps=8)
                    await page.wait_for_timeout(120)
                    await page.mouse.click(tx, ty, delay=90)
                    await page.wait_for_timeout(700)
                    if not await self._is_turnstile_modal_visible(page):
                        self._debug_log(
                            f"turnstile fallback solved at point#{idx + 1} ({point.get('label', 'unknown')})"
                        )
                        return True
                    try:
                        await page.keyboard.press("Space")
                    except Exception:
                        pass
                    await page.wait_for_timeout(280)
                    if not await self._is_turnstile_modal_visible(page):
                        self._debug_log(
                            f"turnstile fallback solved by keyboard at point#{idx + 1} ({point.get('label', 'unknown')})"
                        )
                        return True
            except Exception:
                continue

        return False

    async def _solve_cf_challenge(self, page) -> bool:
        try:
            has_cf_iframe = await page.locator("iframe[src*='challenges.cloudflare.com']").count()
            if has_cf_iframe == 0:
                # Some challenge pages auto-redirect after JS checks; don't force click solver.
                await page.wait_for_timeout(6000)
                return True

            if not await self._prepare_click_solver(page):
                return False
            await self._click_solver.solve_captcha(
                captcha_container=page,
                captcha_type=CaptchaType.CLOUDFLARE_INTERSTITIAL,
            )
            await page.wait_for_timeout(3000)
            return True
        except Exception:
            return False

    async def _solve_turnstile_checkbox(self, page) -> bool:
        if not (await self._is_turnstile_modal_visible(page) or await self._has_turnstile_markers(page)):
            return True

        self._debug_log("turnstile detected, starting solve loop")
        for attempt in range(1, 8):
            if not await self._is_turnstile_modal_visible(page):
                self._debug_log("turnstile modal no longer visible")
                return True

            try:
                deep_iframe_count = await self._count_turnstile_iframes_deep(page)
                self._debug_log(f"turnstile attempt={attempt}, deep_iframes={deep_iframe_count}")
                if deep_iframe_count > 0 and await self._prepare_click_solver(page):
                    await self._click_solver.solve_captcha(
                        captcha_container=page,
                        captcha_type=CaptchaType.CLOUDFLARE_TURNSTILE,
                    )
                    await page.wait_for_timeout(2000)
                    if not await self._is_turnstile_modal_visible(page):
                        self._debug_log(f"turnstile solved by click_solver on attempt={attempt}")
                        return True
            except Exception:
                self._debug_log(f"turnstile solver attempt={attempt} raised exception")

            clicked = await self._click_turnstile_verify_fallback(page)
            if clicked:
                self._debug_log(f"turnstile fallback click triggered on attempt={attempt}")
            else:
                self._debug_log(f"turnstile fallback had no effective click on attempt={attempt}")
            await page.wait_for_timeout(900 if clicked else 1200)

        await page.wait_for_timeout(1000)
        solved = not await self._is_turnstile_modal_visible(page)
        self._debug_log(f"turnstile solve loop finished, solved={solved}")
        return solved

    async def _login_via_linuxdo(self, page) -> tuple[bool, str]:
        if not self.credential:
            return False, "missing linuxdo credential"

        await page.goto(f"{BASE_URL}/login", wait_until="domcontentloaded")
        await page.wait_for_timeout(1200)
        await self._dismiss_blocking_modal(page)
        if await self._is_logged_in(page):
            return True, "session already active"

        clicked, used_selector = await self._click_first(page, LOGIN_BUTTON_SELECTORS)
        if not clicked:
            await self._dismiss_blocking_modal(page)
            clicked, used_selector = await self._click_first(page, LOGIN_BUTTON_SELECTORS)
        if not clicked:
            await take_screenshot(page, "hybgzs_login_button_not_found", self.account_name)
            excerpt = ""
            try:
                excerpt = await page.evaluate(
                    """() => (document.body?.innerText || "").replace(/\\s+/g, " ").slice(0, 180)"""
                )
            except Exception:
                pass
            return False, f"linuxdo login button not found (url={page.url}, excerpt={excerpt})"

        login_submitted = False
        approve_clicked = False
        cf_solved_count = 0

        for _ in range(140):
            if await self._is_logged_in(page):
                state = "logged in"
                if login_submitted:
                    state += " (credential flow)"
                if approve_clicked:
                    state += " (oauth approved)"
                if cf_solved_count:
                    state += f" (cf solved x{cf_solved_count})"
                return True, f"{state}, trigger={used_selector}"

            url = page.url.lower()

            if await self._is_cf_challenge_page(page):
                solved = await self._solve_cf_challenge(page)
                if solved:
                    cf_solved_count += 1
                await page.wait_for_timeout(1200)
                continue

            if "linux.do/login" in url and not login_submitted:
                try:
                    await page.fill("#login-account-name", self.credential.username)
                    await page.fill("#login-account-password", self.credential.password)
                    await page.click("#login-button")
                    login_submitted = True
                except Exception:
                    pass

            if "connect.linux.do" in url:
                try:
                    approve = page.locator("a[href^='/oauth2/approve']").first
                    if await approve.count() > 0:
                        await approve.click(timeout=4000)
                        approve_clicked = True
                except Exception:
                    pass

            await page.wait_for_timeout(1500)

        await take_screenshot(page, "hybgzs_login_timeout", self.account_name)
        return False, f"login timeout, current_url={page.url}"

    async def _query_checkin_today(self, page) -> tuple[bool, bool, str]:
        month = datetime.now().strftime("%Y-%m")
        resp = await self._fetch_json(page, f"/api/checkin/config?month={month}")
        if resp.get("status") != 200:
            return False, False, f"checkin config http={resp.get('status')}"

        payload = resp.get("json")
        if not isinstance(payload, dict):
            return False, False, "checkin config invalid json"

        data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
        has_checked = data.get("hasCheckedInToday")
        if isinstance(has_checked, bool):
            return True, has_checked, ""

        checked_dates = data.get("checkedDates")
        if isinstance(checked_dates, list):
            return True, int(datetime.now().strftime("%d")) in checked_dates, ""

        return True, False, ""

    async def _run_checkin(self, page) -> tuple[bool, dict]:
        ok, done, err = await self._query_checkin_today(page)
        if err and "http=503" in err:
            return True, {"skipped": True, "maintenance": True, "message": "site under maintenance (503)"}
        if ok and done:
            return True, {"already": True, "message": "already checked in today"}

        await page.goto(f"{BASE_URL}/gas-station/checkin", wait_until="domcontentloaded")
        await page.wait_for_timeout(1200)

        try:
            content = (await page.content()).lower()
            if "system under maintenance" in content or "\u7ad9\u70b9\u7ef4\u62a4\u4e2d" in content:
                return True, {"skipped": True, "maintenance": True, "message": "site under maintenance page"}
        except Exception:
            pass

        clicked, selector = await self._click_first(page, CHECKIN_BUTTON_SELECTORS)
        if not clicked:
            ok2, done2, err2 = await self._query_checkin_today(page)
            if err2 and "http=503" in err2:
                return True, {"skipped": True, "maintenance": True, "message": "site under maintenance (503)"}
            if ok2 and done2:
                return True, {"already": True, "message": "already checked in today"}
            await take_screenshot(page, "hybgzs_checkin_button_not_found", self.account_name)
            return False, {"error": f"checkin button not found ({err2 or err})"}

        await page.wait_for_timeout(1200)
        solved_turnstile = False
        turnstile_seen = await self._is_turnstile_modal_visible(page) or await self._has_turnstile_markers(page)
        if turnstile_seen:
            solved_turnstile = await self._solve_turnstile_checkbox(page)
            # After verification attempt, retry once even if solver result is unknown.
            await page.wait_for_timeout(900)
            ok_retry, _ = await self._click_first(page, [selector, *CHECKIN_BUTTON_SELECTORS])
            if ok_retry:
                await page.wait_for_timeout(900)

        err3 = ""
        for idx in range(35):
            ok3, done3, err3 = await self._query_checkin_today(page)
            if ok3 and done3:
                feedback = await self._extract_feedback_text(page)
                return True, {
                    "already": False,
                    "selector": selector,
                    "message": feedback or "checkin completed",
                    "turnstile_solved": solved_turnstile,
                }

            if idx in {8, 16}:
                api_submit = await self._fetch_json(page, "/api/checkin", method="POST")
                text = str((api_submit.get("json") or {}).get("error") or api_submit.get("text") or "")
                if api_submit.get("status") == 200:
                    await page.wait_for_timeout(1200)
                else:
                    need_verify = self._text_contains_turnstile_hint(text) or await self._is_turnstile_modal_visible(page)
                    if not need_verify:
                        need_verify = await self._has_turnstile_markers(page)
                    if need_verify:
                        solved_turnstile = await self._solve_turnstile_checkbox(page) or solved_turnstile
                        await page.wait_for_timeout(900)
                        await self._click_first(page, [selector, *CHECKIN_BUTTON_SELECTORS])
                        await page.wait_for_timeout(900)
                await page.wait_for_timeout(700)

            # Modal may appear later; retry solve during polling.
            if idx in {4, 12, 20, 28} and await self._is_turnstile_modal_visible(page):
                solved_turnstile = await self._solve_turnstile_checkbox(page) or solved_turnstile
                await page.wait_for_timeout(900)
                await self._click_first(page, [selector, *CHECKIN_BUTTON_SELECTORS])
                await page.wait_for_timeout(700)

            await page.wait_for_timeout(2000)

        feedback = await self._extract_feedback_text(page)
        await take_screenshot(page, "hybgzs_checkin_timeout", self.account_name)
        turnstile_open = await self._is_turnstile_modal_visible(page)
        return False, {
            "error": f"checkin not confirmed ({feedback or 'no feedback'}; {err3})",
            "turnstile_open": turnstile_open,
            "turnstile_solved": solved_turnstile,
        }

    async def _wheel_status(self, page) -> tuple[bool, int, str]:
        resp = await self._fetch_json(page, "/api/wheel")
        if resp.get("status") != 200:
            return False, 0, f"wheel status http={resp.get('status')}"

        payload = resp.get("json")
        if not isinstance(payload, dict) or not payload.get("success"):
            text = (resp.get("text") or "")[:200]
            return False, 0, f"wheel status invalid response: {text}"

        data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
        remaining = data.get("remainingSpins")
        if isinstance(remaining, int):
            return True, max(0, remaining), ""
        return True, 0, ""

    async def _wheel_spin_once(self, page) -> tuple[bool, dict]:
        resp = await self._fetch_json(page, "/api/wheel", method="POST")
        if resp.get("status") != 200:
            return False, {"error": f"wheel spin http={resp.get('status')}"}

        payload = resp.get("json")
        if not isinstance(payload, dict) or not payload.get("success"):
            text = (resp.get("text") or "")[:200]
            return False, {"error": f"wheel spin failed: {text}"}

        data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
        prize = data.get("prize") if isinstance(data.get("prize"), dict) else {}
        return True, {
            "message": data.get("message") or "",
            "prize_name": prize.get("name") or "",
            "remaining": data.get("remainingSpins"),
        }

    async def _run_wheel(self, page) -> tuple[bool, dict]:
        if not self.run_wheel:
            return True, {"skipped": True, "message": "wheel disabled"}

        ok, remaining, err = await self._wheel_status(page)
        if not ok:
            return False, {"error": err}
        if remaining <= 0:
            return True, {"spins": 0, "message": "no remaining spins"}

        spins_to_run = remaining if self.max_wheel_spins == 0 else min(remaining, self.max_wheel_spins)
        items = []

        for _ in range(spins_to_run):
            spin_ok, info = await self._wheel_spin_once(page)
            if not spin_ok:
                err = str(info.get("error", "wheel spin failed"))
                if "http=429" in err:
                    return True, {
                        "spins": len(items),
                        "results": items,
                        "rate_limited": True,
                        "message": "wheel rate limited, stop further spins",
                    }
                return False, {"error": err, "results": items}
            items.append(info)
            await page.wait_for_timeout(1500)

        return True, {"spins": len(items), "results": items}

    async def execute(self) -> tuple[bool, dict]:
        print(f"Starting hybgzs flow for {self.account_name}")

        details: list[str] = []
        browser_cookies = self._build_browser_cookies(BASE_URL, self.cookies)
        storage_state_path = self._storage_state_path()
        storage_state = storage_state_path if storage_state_path and os.path.exists(storage_state_path) else None

        async with AsyncCamoufox(
            headless=not self.debug,
            humanize=True,
            locale="en-US",
            geoip=True if self.proxy else False,
            proxy=self.proxy,
            os="macos",
        ) as browser:
            if storage_state_path:
                details.append(f"[cache] storage-state {'hit' if storage_state else 'miss'}")

            if storage_state:
                try:
                    context = await browser.new_context(storage_state=storage_state)
                except Exception as exc:
                    details.append(f"[cache] restore failed, fallback fresh context: {exc}")
                    try:
                        os.remove(storage_state)
                        details.append("[cache] removed invalid storage-state cache")
                    except Exception:
                        pass
                    context = await browser.new_context()
            else:
                context = await browser.new_context()

            page = await context.new_page()

            try:
                solver_ready = await self._prepare_click_solver(page)
                details.append(f"[captcha] solver prepared={solver_ready}")

                if browser_cookies:
                    await context.add_cookies(browser_cookies)
                    details.append(f"[cookie] loaded {len(browser_cookies)} cookies")

                await page.goto(f"{BASE_URL}/dashboard", wait_until="domcontentloaded")
                await page.wait_for_timeout(1200)

                if not await self._is_logged_in(page):
                    login_ok, login_msg = await self._login_via_linuxdo(page)
                    details.append(f"[login] {login_msg}")
                    if not login_ok:
                        return False, {"error": "login failed", "details": details}
                    if storage_state_path:
                        try:
                            await context.storage_state(path=storage_state_path)
                            details.append("[cache] storage-state saved")
                        except Exception as exc:
                            details.append(f"[cache] save failed: {exc}")
                else:
                    if storage_state and not browser_cookies:
                        details.append("[login] session restored from storage-state cache")
                    elif browser_cookies:
                        details.append("[login] session restored from cookies")
                    else:
                        details.append("[login] session already active")
                    if storage_state_path:
                        try:
                            await context.storage_state(path=storage_state_path)
                            details.append("[cache] storage-state saved")
                        except Exception as exc:
                            details.append(f"[cache] save failed: {exc}")

                checkin_ok, checkin_result = await self._run_checkin(page)
                details.append(f"[checkin] {checkin_result}")
                if not checkin_ok:
                    return False, {"error": "checkin failed", "details": details}
                if checkin_result.get("maintenance"):
                    details.append("[maintenance] skip wheel while site is under maintenance")
                    return True, {"display": "hybgzs skipped: maintenance", "details": details}

                wheel_ok, wheel_result = await self._run_wheel(page)
                details.append(f"[wheel] {wheel_result}")
                if not wheel_ok:
                    return False, {"error": "wheel failed", "details": details}

                return True, {"display": "hybgzs done", "details": details}
            except Exception as exc:
                await take_screenshot(page, "hybgzs_execute_exception", self.account_name)
                return False, {"error": f"runtime exception: {exc}", "details": details}
            finally:
                await self._cleanup_click_solver()
                await page.close()
                await context.close()
