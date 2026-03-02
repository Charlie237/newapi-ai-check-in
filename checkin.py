#!/usr/bin/env python3
"""
CheckIn 类
"""

import asyncio
import hashlib
import inspect
import json
import os
import tempfile
from datetime import datetime
from urllib.parse import urlencode, urlparse

from camoufox.async_api import AsyncCamoufox
from curl_cffi import requests as curl_requests

from utils.browser_utils import aliyun_captcha_check, get_random_user_agent, parse_cookies, take_screenshot
from utils.config import AccountConfig, ProviderConfig
from utils.get_cf_clearance import get_cf_clearance
from utils.get_headers import get_curl_cffi_impersonate
from utils.http_utils import proxy_resolve, response_resolve
from utils.mask_utils import mask_username
from utils.topup import topup


class CheckIn:
    """newapi.ai 签到管理类"""

    def __init__(
        self,
        account_name: str,
        account_config: AccountConfig,
        provider_config: ProviderConfig,
        global_proxy: dict | None = None,
        storage_state_dir: str = "storage-states",
    ):
        """初始化签到管理器

        Args:
                account_info: account 用户配置
                proxy_config: 全局代理配置(可选)
        """
        self.account_name = account_name
        self.safe_account_name = "".join(c if c.isalnum() else "_" for c in account_name)
        self.account_config = account_config
        self.provider_config = provider_config

        # 将全局代理存入 account_config.extra，供 get_cdk 和 check_in_status 等函数使用
        if global_proxy:
            self.account_config.extra["global_proxy"] = global_proxy

        # 代理优先级: 账号配置 > 全局配置
        self.camoufox_proxy_config = account_config.proxy if account_config.proxy else global_proxy
        # curl_cffi proxy 转换
        self.http_proxy_config = proxy_resolve(self.camoufox_proxy_config)

        # storage-states 目录
        self.storage_state_dir = storage_state_dir

        os.makedirs(self.storage_state_dir, exist_ok=True)

    async def get_waf_cookies_with_browser(self) -> dict | None:
        """使用 Camoufox 获取 WAF cookies（隐私模式）"""
        print(
            f"ℹ️ {self.account_name}: Starting browser to get WAF cookies (using proxy: {'true' if self.camoufox_proxy_config else 'false'})"
        )

        with tempfile.TemporaryDirectory(prefix=f"camoufox_{self.safe_account_name}_waf_") as tmp_dir:
            print(f"ℹ️ {self.account_name}: Using temporary directory: {tmp_dir}")
            async with AsyncCamoufox(
                persistent_context=True,
                user_data_dir=tmp_dir,
                headless=False,
                humanize=True,
                locale="en-US",
                geoip=True if self.camoufox_proxy_config else False,
                proxy=self.camoufox_proxy_config,
                os="macos",  # 强制使用 macOS 指纹，避免跨平台指纹不一致问题
            ) as browser:
                page = await browser.new_page()

                try:
                    print(f"ℹ️ {self.account_name}: Access login page to get initial cookies")
                    await page.goto(self.provider_config.get_login_url(), wait_until="networkidle")

                    try:
                        await page.wait_for_function('document.readyState === "complete"', timeout=5000)
                    except Exception:
                        await page.wait_for_timeout(3000)

                    if self.provider_config.aliyun_captcha:
                        captcha_check = await aliyun_captcha_check(page, self.account_name)
                        if captcha_check:
                            await page.wait_for_timeout(3000)

                    cookies = await browser.cookies()

                    waf_cookies = {}
                    print(f"ℹ️ {self.account_name}: WAF cookies")
                    for cookie in cookies:
                        cookie_name = cookie.get("name")
                        cookie_value = cookie.get("value")
                        print(f"  📚 Cookie: {cookie_name} (value: {cookie_value})")
                        if cookie_name in ["acw_tc", "cdn_sec_tc", "acw_sc__v2"] and cookie_value is not None:
                            waf_cookies[cookie_name] = cookie_value

                    print(f"ℹ️ {self.account_name}: Got {len(waf_cookies)} WAF cookies after step 1")

                    # 检查是否至少获取到一个 WAF cookie
                    if not waf_cookies:
                        print(f"❌ {self.account_name}: No WAF cookies obtained")
                        return None

                    # 显示获取到的 cookies
                    cookie_names = list(waf_cookies.keys())
                    print(f"✅ {self.account_name}: Successfully got WAF cookies: {cookie_names}")

                    return waf_cookies

                except Exception as e:
                    print(f"❌ {self.account_name}: Error occurred while getting WAF cookies: {e}")
                    return None
                finally:
                    await page.close()

    async def get_aliyun_captcha_cookies_with_browser(self) -> dict | None:
        """使用 Camoufox 获取阿里云验证 cookies"""
        print(
            f"ℹ️ {self.account_name}: Starting browser to get Aliyun captcha cookies (using proxy: {'true' if self.camoufox_proxy_config else 'false'})"
        )

        with tempfile.TemporaryDirectory(prefix=f"camoufox_{self.safe_account_name}_aliyun_captcha_") as tmp_dir:
            print(f"ℹ️ {self.account_name}: Using temporary directory: {tmp_dir}")
            async with AsyncCamoufox(
                persistent_context=True,
                user_data_dir=tmp_dir,
                headless=False,
                humanize=True,
                locale="en-US",
                geoip=True if self.camoufox_proxy_config else False,
                proxy=self.camoufox_proxy_config,
                os="macos",  # 强制使用 macOS 指纹，避免跨平台指纹不一致问题
            ) as browser:
                page = await browser.new_page()

                try:
                    print(f"ℹ️ {self.account_name}: Access login page to get initial cookies")
                    await page.goto(self.provider_config.get_login_url(), wait_until="networkidle")

                    try:
                        await page.wait_for_function('document.readyState === "complete"', timeout=5000)
                    except Exception:
                        await page.wait_for_timeout(3000)

                        # # 提取验证码相关数据
                        # captcha_data = await page.evaluate(
                        #     """() => {
                        #     const data = {};

                        #     // 获取 traceid
                        #     const traceElement = document.getElementById('traceid');
                        #     if (traceElement) {
                        #         const text = traceElement.innerText || traceElement.textContent;
                        #         const match = text.match(/TraceID:\\s*([a-f0-9]+)/i);
                        #         data.traceid = match ? match[1] : null;
                        #     }

                        #     // 获取 window.aliyun_captcha 相关字段
                        #     for (const key in window) {
                        #         if (key.startsWith('aliyun_captcha')) {
                        #             data[key] = window[key];
                        #         }
                        #     }

                        #     // 获取 requestInfo
                        #     if (window.requestInfo) {
                        #         data.requestInfo = window.requestInfo;
                        #     }

                        #     // 获取当前 URL
                        #     data.currentUrl = window.location.href;

                        #     return data;
                        # }"""
                        # )

                        # print(
                        #     f"📋 {self.account_name}: Captcha data extracted: " f"\n{json.dumps(captcha_data, indent=2)}"
                        # )

                        # # 通过 WaitForSecrets 发送验证码数据并等待用户手动验证
                        # from utils.wait_for_secrets import WaitForSecrets

                        # wait_for_secrets = WaitForSecrets()
                        # secret_obj = {
                        #     "CAPTCHA_NEXT_URL": {
                        #         "name": f"{self.account_name} - Aliyun Captcha Verification",
                        #         "description": (
                        #             f"Aliyun captcha verification required.\n"
                        #             f"TraceID: {captcha_data.get('traceid', 'N/A')}\n"
                        #             f"Current URL: {captcha_data.get('currentUrl', 'N/A')}\n"
                        #             f"Please complete the captcha manually in the browser, "
                        #             f"then provide the next URL after verification."
                        #         ),
                        #     }
                        # }

                        # secrets = wait_for_secrets.get(
                        #     secret_obj,
                        #     timeout=300,
                        #     notification={
                        #         "title": "阿里云验证",
                        #         "content": "请在浏览器中完成验证，并提供下一步的 URL。\n"
                        #         f"{json.dumps(captcha_data, indent=2)}\n"
                        #         "📋 操作说明：https://github.com/aceHubert/newapi-ai-check-in/docs/aliyun_captcha/README.md",
                        #     },
                        # )
                        # if not secrets or "CAPTCHA_NEXT_URL" not in secrets:
                        #     print(f"❌ {self.account_name}: No next URL provided " f"for captcha verification")
                        #     return None

                        # next_url = secrets["CAPTCHA_NEXT_URL"]
                        # print(f"🔄 {self.account_name}: Navigating to next URL " f"after captcha: {next_url}")

                        # # 导航到新的 URL
                        # await page.goto(next_url, wait_until="networkidle")

                        try:
                            await page.wait_for_function('document.readyState === "complete"', timeout=5000)
                        except Exception:
                            await page.wait_for_timeout(3000)

                        # 再次检查是否还有 traceid
                        traceid_after = None
                        try:
                            traceid_after = await page.evaluate(
                                """() => {
                                const traceElement = document.getElementById('traceid');
                                if (traceElement) {
                                    const text = traceElement.innerText || traceElement.textContent;
                                    const match = text.match(/TraceID:\\s*([a-f0-9]+)/i);
                                    return match ? match[1] : null;
                                }
                                return null;
                            }"""
                            )
                        except Exception:
                            traceid_after = None

                        if traceid_after:
                            print(
                                f"❌ {self.account_name}: Captcha verification failed, "
                                f"traceid still present: {traceid_after}"
                            )
                            return None

                        print(f"✅ {self.account_name}: Captcha verification successful, " f"traceid cleared")

                    cookies = await browser.cookies()

                    aliyun_captcha_cookies = {}
                    print(f"ℹ️ {self.account_name}: Aliyun Captcha cookies")
                    for cookie in cookies:
                        cookie_name = cookie.get("name")
                        cookie_value = cookie.get("value")
                        print(f"  📚 Cookie: {cookie_name} (value: {cookie_value})")
                        # if cookie_name in ["acw_tc", "cdn_sec_tc", "acw_sc__v2"]
                        # and cookie_value is not None:
                        aliyun_captcha_cookies[cookie_name] = cookie_value

                    print(
                        f"ℹ️ {self.account_name}: "
                        f"Got {len(aliyun_captcha_cookies)} "
                        f"Aliyun Captcha cookies after step 1"
                    )

                    # 检查是否至少获取到一个 Aliyun Captcha cookie
                    if not aliyun_captcha_cookies:
                        print(f"❌ {self.account_name}: " f"No Aliyun Captcha cookies obtained")
                        return None

                    # 显示获取到的 cookies
                    cookie_names = list(aliyun_captcha_cookies.keys())
                    print(f"✅ {self.account_name}: " f"Successfully got Aliyun Captcha cookies: {cookie_names}")

                    return aliyun_captcha_cookies

                except Exception as e:
                    print(f"❌ {self.account_name}: " f"Error occurred while getting Aliyun Captcha cookies, {e}")
                    return None
                finally:
                    await page.close()

    async def get_status_with_browser(self) -> dict | None:
        """使用 Camoufox 获取状态信息并缓存
        Returns:
            状态数据字典
        """
        print(
            f"ℹ️ {self.account_name}: Starting browser to get status (using proxy: {'true' if self.camoufox_proxy_config else 'false'})"
        )

        with tempfile.TemporaryDirectory(prefix=f"camoufox_{self.safe_account_name}_status_") as tmp_dir:
            print(f"ℹ️ {self.account_name}: Using temporary directory: {tmp_dir}")
            async with AsyncCamoufox(
                user_data_dir=tmp_dir,
                persistent_context=True,
                headless=False,
                humanize=True,
                locale="en-US",
                geoip=True if self.camoufox_proxy_config else False,
                proxy=self.camoufox_proxy_config,
                os="macos",  # 强制使用 macOS 指纹，避免跨平台指纹不一致问题
            ) as browser:
                page = await browser.new_page()

                try:
                    print(f"ℹ️ {self.account_name}: Access status page to get status from localStorage")
                    await page.goto(self.provider_config.get_login_url(), wait_until="networkidle")

                    try:
                        await page.wait_for_function('document.readyState === "complete"', timeout=5000)
                    except Exception:
                        await page.wait_for_timeout(3000)

                    if self.provider_config.aliyun_captcha:
                        captcha_check = await aliyun_captcha_check(page, self.account_name)
                        if captcha_check:
                            await page.wait_for_timeout(3000)

                    # 从 localStorage 获取 status
                    status_data = None
                    try:
                        status_str = await page.evaluate("() => localStorage.getItem('status')")
                        if status_str:
                            status_data = json.loads(status_str)
                            print(f"✅ {self.account_name}: Got status from localStorage")
                        else:
                            print(f"⚠️ {self.account_name}: No status found in localStorage")
                    except Exception as e:
                        print(f"⚠️ {self.account_name}: Error reading status from localStorage: {e}")

                    return status_data

                except Exception as e:
                    print(f"❌ {self.account_name}: Error occurred while getting status: {e}")
                    return None
                finally:
                    await page.close()

    async def get_auth_client_id(self, session: curl_requests.Session, headers: dict, provider: str) -> dict:
        """获取状态信息

        Args:
            session: curl_cffi Session 客户端
            headers: 请求头
            provider: 提供商类型 (github/linuxdo)

        Returns:
            包含 success 和 client_id 或 error 的字典
        """
        try:
            response = session.get(self.provider_config.get_status_url(), headers=headers, timeout=30)

            if response.status_code == 200:
                data = response_resolve(response, f"get_auth_client_id_{provider}", self.account_name)
                if data is None:

                    # 尝试从浏览器 localStorage 获取状态
                    # print(f"ℹ️ {self.account_name}: Getting status from browser")
                    # try:
                    #     status_data = await self.get_status_with_browser()
                    #     if status_data:
                    #         oauth = status_data.get(f"{provider}_oauth", False)
                    #         if not oauth:
                    #             return {
                    #                 "success": False,
                    #                 "error": f"{provider} OAuth is not enabled.",
                    #             }

                    #         client_id = status_data.get(f"{provider}_client_id", "")
                    #         if client_id:
                    #             print(f"✅ {self.account_name}: Got client ID from localStorage: " f"{client_id}")
                    #             return {
                    #                 "success": True,
                    #                 "client_id": client_id,
                    #             }
                    # except Exception as browser_err:
                    #     print(f"⚠️ {self.account_name}: Failed to get status from browser: " f"{browser_err}")

                    return {
                        "success": False,
                        "error": "Failed to get client id: Invalid response type (saved to logs)",
                    }

                if data.get("success"):
                    status_data = data.get("data", {})
                    oauth = status_data.get(f"{provider}_oauth", False)
                    if not oauth:
                        return {
                            "success": False,
                            "error": f"{provider} OAuth is not enabled.",
                        }

                    client_id = str(status_data.get(f"{provider}_client_id", "")).strip()
                    if not client_id:
                        return {
                            "success": False,
                            "error": f"{provider} client_id is empty in status response.",
                        }
                    return {
                        "success": True,
                        "client_id": client_id,
                    }
                else:
                    error_msg = data.get("message", "Unknown error")
                    return {
                        "success": False,
                        "error": f"Failed to get client id: {error_msg}",
                    }
            return {
                "success": False,
                "error": f"Failed to get client id: HTTP {response.status_code}",
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to get client id, {e}",
            }

    async def get_auth_state_with_browser(self) -> dict:
        """使用 Camoufox 获取认证 URL 和 cookies

        Args:
            status: 要存储到 localStorage 的状态数据
            wait_for_url: 要等待的 URL 模式

        Returns:
            包含 success、url、cookies 或 error 的字典
        """
        print(
            f"ℹ️ {self.account_name}: Starting browser to get auth state (using proxy: {'true' if self.camoufox_proxy_config else 'false'})"
        )

        with tempfile.TemporaryDirectory(prefix=f"camoufox_{self.safe_account_name}_auth_") as tmp_dir:
            print(f"ℹ️ {self.account_name}: Using temporary directory: {tmp_dir}")
            async with AsyncCamoufox(
                user_data_dir=tmp_dir,
                persistent_context=True,
                headless=False,
                humanize=True,
                locale="en-US",
                geoip=True if self.camoufox_proxy_config else False,
                proxy=self.camoufox_proxy_config,
                os="macos",  # 强制使用 macOS 指纹，避免跨平台指纹不一致问题
            ) as browser:
                page = await browser.new_page()

                try:
                    # 1. Open the login page first
                    print(f"ℹ️ {self.account_name}: Opening login page")
                    await page.goto(self.provider_config.get_login_url(), wait_until="networkidle")

                    # Wait for page to be fully loaded
                    try:
                        await page.wait_for_function('document.readyState === "complete"', timeout=5000)
                    except Exception:
                        await page.wait_for_timeout(3000)

                    if self.provider_config.aliyun_captcha:
                        captcha_check = await aliyun_captcha_check(page, self.account_name)
                        if captcha_check:
                            await page.wait_for_timeout(3000)

                    response = await page.evaluate(
                        f"""async () => {{
                            try{{
                                const response = await fetch('{self.provider_config.get_auth_state_url()}');
                                const data = await response.json();
                                return data;
                            }}catch(e){{
                                return {{
                                    success: false,
                                    message: e.message
                                }};
                            }}
                        }}"""
                    )

                    if response and "data" in response:
                        cookies = await browser.cookies()
                        return {
                            "success": True,
                            "state": response.get("data"),
                            "cookies": cookies,
                        }

                    return {"success": False, "error": f"Failed to get state, \n{json.dumps(response, indent=2)}"}

                except Exception as e:
                    print(f"❌ {self.account_name}: Failed to get state, {e}")
                    await take_screenshot(page, "auth_url_error", self.account_name)
                    return {"success": False, "error": "Failed to get state"}
                finally:
                    await page.close()

    async def get_auth_state(
        self,
        session: curl_requests.Session,
        headers: dict,
    ) -> dict:
        """获取认证状态
        
        使用 curl_cffi Session 发送请求。Session 可在创建时设置全局 impersonate。
        
        Args:
            session: curl_cffi Session 客户端（已包含 cookies，可能已设置 impersonate）
            headers: 请求头
        """
        try:
            response = session.get(
                self.provider_config.get_auth_state_url(),
                headers=headers,
                timeout=30,
            )

            if response.status_code == 200:
                json_data = response_resolve(response, "get_auth_state", self.account_name)
                if json_data is None:
                    return {
                        "success": False,
                        "error": "Failed to get auth state: Invalid response type (saved to logs)",
                    }

                # 检查响应是否成功
                if json_data.get("success"):
                    auth_data = json_data.get("data")

                    # 将 curl_cffi Cookies 转换为 Camoufox 格式
                    result_cookies = []
                    parsed_domain = urlparse(self.provider_config.origin).netloc

                    print(f"ℹ️ {self.account_name}: Got {len(response.cookies)} cookies from auth state request")
                    for cookie in response.cookies.jar:
                        # 从 _rest 中获取 HttpOnly 和 SameSite，确保类型正确
                        http_only_raw = cookie._rest.get("HttpOnly", False)
                        http_only = bool(http_only_raw) if http_only_raw is not None else False
                        
                        same_site_raw = cookie._rest.get("SameSite", "Lax")
                        same_site = str(same_site_raw) if same_site_raw else "Lax"
                        
                        # secure 也需要确保是布尔值
                        secure = bool(cookie.secure) if cookie.secure is not None else False
                        
                        print(
                            f"  📚 Cookie: {cookie.name} (Domain: {cookie.domain}, "
                            f"Path: {cookie.path}, Expires: {cookie.expires}, "
                            f"HttpOnly: {http_only}, Secure: {secure}, "
                            f"SameSite: {same_site})"
                        )
                        # 构建 cookie 字典，Camoufox 要求字段类型严格
                        cookie_dict = {
                            "name": cookie.name,
                            "domain": cookie.domain if cookie.domain else parsed_domain,
                            "value": cookie.value,
                            "path": cookie.path if cookie.path else "/",
                            "secure": secure,
                            "httpOnly": http_only,
                            "sameSite": same_site,
                        }
                        # 只有当 expires 是有效的数值时才添加
                        if cookie.expires is not None:
                            cookie_dict["expires"] = float(cookie.expires)
                        result_cookies.append(cookie_dict)

                    return {
                        "success": True,
                        "state": auth_data,
                        "cookies": result_cookies,
                    }
                else:
                    error_msg = json_data.get("message", "Unknown error")
                    return {
                        "success": False,
                        "error": f"Failed to get auth state: {error_msg}",
                    }
            return {
                "success": False,
                "error": f"Failed to get auth state: HTTP {response.status_code}",
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to get auth state, {e}",
            }

    async def get_user_info_with_browser(self, auth_cookies: list[dict]) -> dict:
        """使用 Camoufox 获取用户信息

        Returns:
            包含 success、quota、used_quota 或 error 的字典
        """
        print(
            f"ℹ️ {self.account_name}: Starting browser to get user info (using proxy: {'true' if self.camoufox_proxy_config else 'false'})"
        )

        with tempfile.TemporaryDirectory(prefix=f"camoufox_{self.safe_account_name}_user_info_") as tmp_dir:
            print(f"ℹ️ {self.account_name}: Using temporary directory: {tmp_dir}")
            async with AsyncCamoufox(
                user_data_dir=tmp_dir,
                persistent_context=True,
                headless=False,
                humanize=True,
                locale="en-US",
                geoip=True if self.camoufox_proxy_config else False,
                proxy=self.camoufox_proxy_config,
                os="macos",  # 强制使用 macOS 指纹，避免跨平台指纹不一致问题
            ) as browser:
                page = await browser.new_page()

                browser.add_cookies(auth_cookies)

                try:
                    # 1. 打开登录页面
                    print(f"ℹ️ {self.account_name}: Opening main page")
                    await page.goto(self.provider_config.origin, wait_until="networkidle")

                    # 等待页面完全加载
                    try:
                        await page.wait_for_function('document.readyState === "complete"', timeout=5000)
                    except Exception:
                        await page.wait_for_timeout(3000)

                    if self.provider_config.aliyun_captcha:
                        captcha_check = await aliyun_captcha_check(page, self.account_name)
                        if captcha_check:
                            await page.wait_for_timeout(3000)

                    # 获取用户信息
                    response = await page.evaluate(
                        f"""async () => {{
                           const response = await fetch(
                               '{self.provider_config.get_user_info_url()}'
                           );
                           const data = await response.json();
                           return data;
                        }}"""
                    )

                    if response and "data" in response:
                        user_data = response.get("data", {})
                        quota = round(user_data.get("quota", 0) / 500000, 2)
                        used_quota = round(user_data.get("used_quota", 0) / 500000, 2)
                        bonus_quota = round(user_data.get("bonus_quota", 0) / 500000, 2)
                        print(
                            f"✅ {self.account_name}: "
                            f"Current balance: ${quota}, Used: ${used_quota}, Bonus: ${bonus_quota}"
                        )
                        return {
                            "success": True,
                            "quota": quota,
                            "used_quota": used_quota,
                            "bonus_quota": bonus_quota,
                            "display": f"Current balance: ${quota}, Used: ${used_quota}, Bonus: ${bonus_quota}",
                        }

                    return {
                        "success": False,
                        "error": f"Failed to get user info, \n{json.dumps(response, indent=2)}",
                    }

                except Exception as e:
                    print(f"❌ {self.account_name}: Failed to get user info, {e}")
                    await take_screenshot(page, "user_info_error", self.account_name)
                    return {"success": False, "error": "Failed to get user info"}
                finally:
                    await page.close()

    async def get_user_info(self, session: curl_requests.Session, headers: dict) -> dict:
        """获取用户信息"""
        try:
            response = session.get(self.provider_config.get_user_info_url(), headers=headers, timeout=30)

            if response.status_code == 200:
                json_data = response_resolve(response, "get_user_info", self.account_name)
                if json_data is None:
                    # 尝试从浏览器获取用户信息
                    # print(f"ℹ️ {self.account_name}: Getting user info from browser")
                    # try:
                    #     user_info_result = await self.get_user_info_with_browser()
                    #     if user_info_result.get("success"):
                    #         return user_info_result
                    #     else:
                    #         error_msg = user_info_result.get("error", "Unknown error")
                    #         print(f"⚠️ {self.account_name}: {error_msg}")
                    # except Exception as browser_err:
                    #     print(
                    #         f"⚠️ {self.account_name}: "
                    #         f"Failed to get user info from browser: {browser_err}"
                    #     )

                    return {
                        "success": False,
                        "error": "Failed to get user info: Invalid response type (saved to logs)",
                    }

                if json_data.get("success"):
                    user_data = json_data.get("data", {})
                    quota = round(user_data.get("quota", 0) / 500000, 2)
                    used_quota = round(user_data.get("used_quota", 0) / 500000, 2)
                    bonus_quota = round(user_data.get("bonus_quota", 0) / 500000, 2)
                    return {
                        "success": True,
                        "quota": quota,
                        "used_quota": used_quota,
                        "bonus_quota": bonus_quota,
                        "display": f"Current balance: ${quota}, Used: ${used_quota}, Bonus: ${bonus_quota}",
                    }
                else:
                    error_msg = json_data.get("message", "Unknown error")
                    return {
                        "success": False,
                        "error": f"Failed to get user info: {error_msg}",
                    }
            return {
                "success": False,
                "error": f"Failed to get user info: HTTP {response.status_code}",
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to get user info, {e}",
            }

    def execute_check_in(
        self,
        session: curl_requests.Session,
        headers: dict,
        api_user: str | int,
    ) -> dict:
        """执行签到请求
        
        Returns:
            包含 success, message, data 等信息的字典
        """
        print(f"🌐 {self.account_name}: Executing check-in")

        checkin_headers = headers.copy()
        checkin_headers.update({"Content-Type": "application/json", "X-Requested-With": "XMLHttpRequest"})

        check_in_url = self.provider_config.get_check_in_url(api_user)
        if not check_in_url:
            print(f"❌ {self.account_name}: No check-in URL configured")
            return {"success": False, "error": "No check-in URL configured"}

        response = session.post(check_in_url, headers=checkin_headers, timeout=30)

        print(f"📨 {self.account_name}: Response status code {response.status_code}")

        # 尝试解析响应（200 或 400 都可能包含有效的 JSON）
        if response.status_code in [200, 400]:
            json_data = response_resolve(response, "execute_check_in", self.account_name)
            if json_data is None:
                # 如果不是 JSON 响应（可能是 HTML），检查是否包含成功标识
                if "success" in response.text.lower():
                    print(f"✅ {self.account_name}: Check-in successful!")
                    return {"success": True, "message": "Check-in successful"}
                else:
                    print(f"❌ {self.account_name}: Check-in failed - Invalid response format")
                    return {"success": False, "error": "Invalid response format"}

            # 检查签到结果
            message = json_data.get("message", json_data.get("msg", ""))

            if (
                json_data.get("ret") == 1
                or json_data.get("code") == 0
                or json_data.get("success")
                or "已经签到" in message
                or "签到成功" in message
            ):
                # 提取签到数据
                check_in_data = json_data.get("data", {})
                checkin_date = check_in_data.get("checkin_date", "")
                quota_awarded = check_in_data.get("quota_awarded", 0)
                
                if quota_awarded:
                    quota_display = round(quota_awarded / 500000, 2)
                    print(f"✅ {self.account_name}: Check-in successful! Date: {checkin_date}, Quota awarded: ${quota_display}")
                else:
                    print(f"✅ {self.account_name}: Check-in successful! {message}")
                
                return {
                    "success": True,
                    "message": message or "Check-in successful",
                    "data": check_in_data,
                }
            else:
                error_msg = json_data.get("msg", json_data.get("message", "Unknown error"))
                print(f"❌ {self.account_name}: Check-in failed - {error_msg}")
                error_text = str(error_msg).lower()
                if (
                    "turnstile" in error_text
                    or "人机验证" in error_text
                    or "token 为空" in error_text
                    or "captcha" in error_text
                ):
                    return {
                        "success": False,
                        "error": error_msg,
                        "requires_turnstile": True,
                    }
                return {"success": False, "error": error_msg}
        else:
            print(f"❌ {self.account_name}: Check-in failed - HTTP {response.status_code}")
            return {"success": False, "error": f"HTTP {response.status_code}"}

    async def execute_topup(
        self,
        headers: dict,
        cookies: dict,
        api_user: str | int,
        topup_interval: int = 60,
    ) -> dict:
        """执行完整的 CDK 获取和充值流程

        直接调用 get_cdk 生成器函数，每次 yield 一个 CDK 字符串并执行 topup
        每次 topup 之间保持间隔时间，如果 topup 失败则停止
        
        支持同步生成器和异步生成器两种类型的 get_cdk 函数

        Args:
            headers: 请求头
            cookies: cookies 字典
            api_user: API 用户 ID（通过参数传递，因为登录方式可能不同）
            topup_interval: 多次 topup 之间的间隔时间（秒），默认 60 秒

        Returns:
            包含 success, topup_count, errors 等信息的字典
        """
        # 检查是否配置了 get_cdk 函数
        if not self.provider_config.get_cdk:
            print(f"ℹ️ {self.account_name}: No get_cdk function configured for provider {self.provider_config.name}")
            return {
                "success": True,
                "topup_count": 0,
                "topup_success_count": 0,
                "error": "",
            }

        # 构建 topup 请求头
        topup_headers = headers.copy()
        topup_headers.update({
            "Referer": f"{self.provider_config.origin}/console/topup",
            "Origin": self.provider_config.origin,
            self.provider_config.api_user_key: f"{api_user}",
        })

        results = {
            "success": True,
            "topup_count": 0,
            "topup_success_count": 0,
            "error": "",
        }

        # 调用 get_cdk 函数，返回同步生成器或异步生成器
        # 优先兼容新签名：get_cdk(account_config, runtime_cookies)
        get_cdk_func = self.provider_config.get_cdk
        try:
            sig = inspect.signature(get_cdk_func)
            supports_runtime_cookies = (
                any(p.kind == inspect.Parameter.VAR_POSITIONAL for p in sig.parameters.values())
                or len(sig.parameters) >= 2
            )
        except Exception:
            supports_runtime_cookies = False

        if supports_runtime_cookies:
            cdk_generator = get_cdk_func(self.account_config, cookies)
        else:
            cdk_generator = get_cdk_func(self.account_config)
        
        topup_count = 0
        error_msg = ""

        # 内部函数：处理单个 CDK 结果
        async def process_cdk_result(success: bool, data: dict) -> bool:
            """处理单个 CDK 结果，返回是否应该继续
            
            Args:
                success: 是否成功获取 CDK
                data: 包含 code 或 error 的字典
                
            Returns:
                bool: True 继续处理下一个，False 停止处理
            """
            nonlocal topup_count, error_msg
            
            # 如果获取 CDK 失败，停止处理
            if not success:
                error_msg = data.get("error", "Failed to get CDK")
                results["success"] = False
                results["error"] = error_msg
                print(f"❌ {self.account_name}: Failed to get CDK - {error_msg}, stopping topup process")
                return False
            
            # 获取 code
            cdk = data.get("code", "")
            
            # 如果 code 为空，表示不需要充值，继续处理下一个
            if not cdk:
                print(f"ℹ️ {self.account_name}: No CDK to topup (code is empty), continuing...")
                return True
            
            # 如果不是第一个 CDK，等待间隔时间
            if topup_count > 0 and topup_interval > 0:
                print(f"⏳ {self.account_name}: Waiting {topup_interval} seconds before next topup...")
                await asyncio.sleep(topup_interval)

            topup_count += 1
            print(f"💰 {self.account_name}: Executing topup #{topup_count} with CDK: {cdk}")

            topup_result = topup(
                provider_config=self.provider_config,
                account_config=self.account_config,
                headers=topup_headers,
                cookies=cookies,
                key=cdk,
            )

            results["topup_count"] += 1

            if topup_result.get("success"):
                results["topup_success_count"] += 1
                if not topup_result.get("already_used"):
                    print(f"✅ {self.account_name}: Topup #{topup_count} successful")
                return True  # 继续处理下一个
            else:
                # topup 失败，记录错误并停止
                error_msg = topup_result.get("error", "Topup failed")
                results["success"] = False
                results["error"] = error_msg
                print(f"❌ {self.account_name}: Topup #{topup_count} failed, stopping topup process")
                return False  # 停止处理

        # 检查是否是异步生成器
        if inspect.isasyncgen(cdk_generator):
            # 异步生成器，使用 async for
            async for success, data in cdk_generator:
                should_continue = await process_cdk_result(success, data)
                if not should_continue:
                    break
        else:
            # 同步生成器，使用普通 for
            for success, data in cdk_generator:
                should_continue = await process_cdk_result(success, data)
                if not should_continue:
                    break

        if topup_count == 0:
            print(f"ℹ️ {self.account_name}: No CDK available for topup")
        elif results["topup_success_count"] > 0:
            print(f"✅ {self.account_name}: Total {results['topup_success_count']}/{results['topup_count']} topup(s) successful")

        return results

    def _get_provider_cookie_cache_file_path(self, username: str) -> str:
        """获取 provider 账号密码登录的 cookie 缓存文件路径。"""
        identity = f'{self.provider_config.origin}|{username}'
        identity_hash = hashlib.sha256(identity.encode('utf-8')).hexdigest()[:16]
        return f'{self.storage_state_dir}/provider_{identity_hash}_cookie_cache.json'

    def _load_provider_cookie_cache(self, cache_file_path: str) -> dict | None:
        """读取 provider 账号密码登录缓存。"""
        try:
            if not os.path.exists(cache_file_path):
                return None
            with open(cache_file_path, encoding='utf-8') as f:
                cache_data = json.load(f)

            cookies = parse_cookies(cache_data.get('cookies', {}))
            api_user = cache_data.get('api_user')
            if not cookies or not api_user:
                print(f'⚠️ {self.account_name}: Provider cookie cache exists but is incomplete, ignoring')
                return None
            return {
                'cookies': cookies,
                'api_user': api_user,
                'updated_at': cache_data.get('updated_at', ''),
            }
        except Exception as e:
            print(f'⚠️ {self.account_name}: Failed to read provider cookie cache: {e}')
            return None

    def _save_provider_cookie_cache(self, cache_file_path: str, cookies: dict, api_user: str | int) -> None:
        """保存 provider 账号密码登录缓存。"""
        try:
            cache_data = {
                'provider': self.provider_config.name,
                'origin': self.provider_config.origin,
                'api_user': str(api_user),
                'cookies': cookies,
                'updated_at': datetime.now().isoformat(),
            }
            with open(cache_file_path, 'w', encoding='utf-8') as f:
                json.dump(cache_data, f, ensure_ascii=False)
            print(f'✅ {self.account_name}: Provider cookie cache updated: {cache_file_path}')
        except Exception as e:
            print(f'⚠️ {self.account_name}: Failed to save provider cookie cache: {e}')

    def _extract_provider_cookies(self, session: curl_requests.Session) -> dict:
        """从 session 中提取当前 provider 域名相关 cookies。"""
        provider_domain = urlparse(self.provider_config.origin).netloc.lstrip('.').lower()
        cookies = {}

        for cookie in session.cookies.jar:
            name = getattr(cookie, 'name', None)
            value = getattr(cookie, 'value', None)
            domain = (getattr(cookie, 'domain', '') or '').lstrip('.').lower()

            if not name or value is None:
                continue

            # 匹配 provider domain 及其子域。
            if (
                not domain
                or domain == provider_domain
                or domain.endswith('.' + provider_domain)
                or provider_domain.endswith('.' + domain)
            ):
                cookies[name] = value

        return cookies

    async def sign_in_with_password(
        self,
        username: str,
        password: str,
        bypass_cookies: dict,
        common_headers: dict,
    ) -> tuple[bool, dict]:
        """使用用户名/邮箱 + 密码走标准 New API 登录链路，再复用 cookies 完成签到。"""
        print(
            f"ℹ️ {self.account_name}: Executing check-in with password account "
            f"({mask_username(username)}) (using proxy: {'true' if self.http_proxy_config else 'false'})"
        )

        user_agent = common_headers.get('User-Agent', '')
        impersonate = get_curl_cffi_impersonate(user_agent)
        if impersonate:
            print(f'ℹ️ {self.account_name}: Using curl_cffi Session with impersonate={impersonate}')

        cache_file_path = self._get_provider_cookie_cache_file_path(username)
        cached_auth = self._load_provider_cookie_cache(cache_file_path)
        cache_status = "miss"
        if cached_auth:
            print(
                f"ℹ️ {self.account_name}: Trying password-login cookie cache "
                f"(updated_at={cached_auth.get('updated_at') or 'unknown'})"
            )
            cached_cookies = cached_auth.get('cookies', {})
            cached_api_user = cached_auth.get('api_user')
            # Keep fresh bypass/WAF cookies from current run authoritative.
            # Old cached anti-bot cookies (e.g. acw_tc/cdn_sec_tc) can expire quickly
            # and would otherwise overwrite fresh values, causing false cache "stale".
            merged_cookies = {**cached_cookies, **bypass_cookies}
            success, user_info = await self.check_in_with_cookies(
                merged_cookies,
                common_headers,
                cached_api_user,
                impersonate,
            )
            if success:
                print(f'✅ {self.account_name}: Password-login cookie cache is valid')
                user_info = user_info or {}
                user_info["cache_status"] = "hit"
                return True, user_info
            print(f'⚠️ {self.account_name}: Password-login cookie cache is invalid, fallback to password login')
            cache_status = "stale"

        session = curl_requests.Session(impersonate=impersonate, proxy=self.http_proxy_config, timeout=30)
        try:
            session.cookies.update(bypass_cookies)

            headers = common_headers.copy()
            headers[self.provider_config.api_user_key] = '-1'
            headers['Referer'] = self.provider_config.get_login_url()
            headers['Origin'] = self.provider_config.origin
            headers['Content-Type'] = 'application/json'

            login_payload = {'username': username, 'password': password}
            login_url = f'{self.provider_config.origin}/api/user/login'

            # 尝试读取 status，兼容 turnstile 参数。
            turnstile_token = ''
            try:
                status_resp = session.get(self.provider_config.get_status_url(), headers=headers, timeout=30)
                status_json = response_resolve(status_resp, 'provider_password_status', self.account_name)
                if status_json and status_json.get('success'):
                    status_data = status_json.get('data', {})
                    if status_data.get('turnstile_check'):
                        turnstile_token = status_data.get('turnstile_token') or ''
            except Exception as status_err:
                print(f'⚠️ {self.account_name}: Failed to read status before password login: {status_err}')

            if turnstile_token:
                login_url = f'{login_url}?turnstile={turnstile_token}'
            else:
                login_url = f'{login_url}?turnstile='

            response = session.post(login_url, json=login_payload, headers=headers, timeout=30)
            login_json = response_resolve(response, 'password_login', self.account_name)
            if login_json is None:
                return False, {
                    'error': 'Password login got non-JSON response (possibly WAF challenge)',
                    'cache_status': cache_status,
                }

            if not login_json.get('success'):
                error_msg = login_json.get('message', 'Password login failed')
                return False, {'error': error_msg, 'cache_status': cache_status}

            login_data = login_json.get('data') or {}
            api_user = login_data.get('id')

            # 某些站点登录返回可能不带完整 data，尝试通过 /api/user/self 补全 id。
            if not api_user:
                user_info_resp = session.get(self.provider_config.get_user_info_url(), headers=headers, timeout=30)
                user_info_json = response_resolve(user_info_resp, 'password_user_info', self.account_name)
                if user_info_json and user_info_json.get('success'):
                    api_user = (user_info_json.get('data') or {}).get('id')

            if not api_user:
                return False, {
                    'error': 'Password login succeeded but api_user was not found',
                    'cache_status': cache_status,
                }

            user_cookies = self._extract_provider_cookies(session)
            if not user_cookies:
                return False, {
                    'error': 'Password login succeeded but cookies are empty',
                    'cache_status': cache_status,
                }

            merged_cookies = {**bypass_cookies, **user_cookies}
            success, user_info = await self.check_in_with_cookies(
                merged_cookies,
                common_headers,
                api_user,
                impersonate,
            )
            if success:
                self._save_provider_cookie_cache(cache_file_path, user_cookies, api_user)
            user_info = user_info or {}
            user_info["cache_status"] = cache_status
            return success, user_info

        except Exception as e:
            print(f'❌ {self.account_name}: Error occurred during password login process - {e}')
            return False, {'error': 'Password login process error', 'cache_status': cache_status}
        finally:
            session.close()

    async def check_in_with_cookies(
        self,
        cookies: dict,
        common_headers: dict,
        api_user: str | int,
        impersonate: str = "firefox135",
    ) -> tuple[bool, dict]:
        """使用已有 cookies 执行签到操作
        
        Args:
            cookies: cookies 字典
            common_headers: 公用请求头（包含 User-Agent 和可能的 Client Hints）
            api_user: API 用户 ID
        """
        print(
            f"ℹ️ {self.account_name}: Executing check-in with existing cookies (using proxy: {'true' if self.http_proxy_config else 'false'})"
        )

        session = curl_requests.Session(impersonate=impersonate, proxy=self.http_proxy_config, timeout=30)
        
        try:
            # 打印 cookies 的键和值
            print(f"ℹ️ {self.account_name}: Cookies to be used:")
            for key, value in cookies.items():
                print(f"  📚 {key}: {value[:50] if len(value) > 50 else value}{'...' if len(value) > 50 else ''}")
            session.cookies.update(cookies)

            # 使用传入的公用请求头，并添加动态头部
            headers = common_headers.copy()
            headers[self.provider_config.api_user_key] = f"{api_user}"
            headers["Referer"] = self.provider_config.get_login_url()
            headers["Origin"] = self.provider_config.origin

            # 检查是否需要手动签到
            if self.provider_config.needs_manual_check_in():
                # 如果配置了签到状态查询，先检查是否已签到
                check_in_status_func = self.provider_config.get_check_in_status_func()
                if check_in_status_func:
                    checked_in_today = check_in_status_func(
                        provider_config=self.provider_config,
                        account_config=self.account_config,
                        cookies=cookies,
                        headers=headers,
                    )
                    if checked_in_today:
                        print(f"ℹ️ {self.account_name}: Already checked in today, skipping check-in")
                    else:
                        # 未签到，执行签到
                        check_in_result = self.execute_check_in(session, headers, api_user)
                        if not check_in_result.get("success"):
                            if (
                                check_in_result.get("requires_turnstile")
                                and self.provider_config.name == "runawaytime"
                                and self.provider_config.needs_manual_topup()
                            ):
                                print(
                                    f"⚠️ {self.account_name}: Check-in requires Turnstile, "
                                    "skip hard-fail and continue topup flow for runawaytime"
                                )
                            else:
                                return False, {"error": check_in_result.get("error", "Check-in failed")}
                        # 签到成功后再次查询状态（显示最新状态）
                        if check_in_result.get("success"):
                            check_in_status_func(
                                provider_config=self.provider_config,
                                account_config=self.account_config,
                                cookies=cookies,
                                headers=headers,
                            )
                else:
                    # 没有配置签到状态查询函数，直接执行签到
                    check_in_result = self.execute_check_in(session, headers, api_user)
                    if not check_in_result.get("success"):
                        if (
                            check_in_result.get("requires_turnstile")
                            and self.provider_config.name == "runawaytime"
                            and self.provider_config.needs_manual_topup()
                        ):
                            print(
                                f"⚠️ {self.account_name}: Check-in requires Turnstile, "
                                "skip hard-fail and continue topup flow for runawaytime"
                            )
                        else:
                            return False, {"error": check_in_result.get("error", "Check-in failed")}
            else:
                print(f"ℹ️ {self.account_name}: Check-in completed automatically (triggered by user info request)")

            # 如果需要手动 topup（配置了 topup_path 和 get_cdk），执行 topup
            if self.provider_config.needs_manual_topup():
                print(f"ℹ️ {self.account_name}: Provider requires manual topup, executing...")
                topup_result = await self.execute_topup(headers, cookies, api_user)
                if topup_result.get("topup_count", 0) > 0:
                    print(
                        f"ℹ️ {self.account_name}: Topup completed - "
                        f"{topup_result.get('topup_success_count', 0)}/{topup_result.get('topup_count', 0)} successful"
                    )
                if not topup_result.get("success"):
                    error_msg = topup_result.get("error") or "Topup failed"
                    print(f"❌ {self.account_name}: Topup failed, stopping check-in process")
                    return False, {"error": error_msg}

            user_info = await self.get_user_info(session, headers)
            if user_info and user_info.get("success"):
                success_msg = user_info.get("display", "User info retrieved successfully")
                print(f"✅ {self.account_name}: {success_msg}")
                return True, user_info
            elif user_info:
                error_msg = user_info.get("error", "Unknown error")
                print(f"❌ {self.account_name}: {error_msg}")
                return False, {"error": "Failed to get user info"}
            else:
                return False, {"error": "No user info available"}

        except Exception as e:
            print(f"❌ {self.account_name}: Error occurred during check-in process - {e}")
            return False, {"error": "Error occurred during check-in process"}
        finally:
            session.close()

    async def check_in_with_github(
        self,
        username: str,
        password: str,
        bypass_cookies: dict,
        common_headers: dict,
    ) -> tuple[bool, dict]:
        """使用 GitHub 账号执行签到操作
        
        Args:
            username: GitHub 用户名
            password: GitHub 密码
            bypass_cookies: bypass cookies
            common_headers: 公用请求头（包含 User-Agent 和可能的 Client Hints）
        """
        print(
            f"ℹ️ {self.account_name}: Executing check-in with GitHub account (using proxy: {'true' if self.http_proxy_config else 'false'})"
        )

        # 根据 User-Agent 自动推断 impersonate 值，在 Session 上设置全局 impersonate
        user_agent = common_headers.get("User-Agent", "")
        impersonate = get_curl_cffi_impersonate(user_agent)
        
        session = curl_requests.Session(impersonate=impersonate, proxy=self.http_proxy_config, timeout=30)
        if impersonate:
            print(f"ℹ️ {self.account_name}: Using curl_cffi Session with impersonate={impersonate}")
        
        try:
            session.cookies.update(bypass_cookies)

            # 使用传入的公用请求头，并添加动态头部
            headers = common_headers.copy()
            headers[self.provider_config.api_user_key] = "-1"
            headers["Referer"] = self.provider_config.get_login_url()
            headers["Origin"] = self.provider_config.origin

            # 获取 OAuth 客户端 ID
            # 优先使用 provider_config 中的 client_id
            if self.provider_config.github_client_id:
                client_id_result = {
                    "success": True,
                    "client_id": self.provider_config.github_client_id,
                }
                print(f"ℹ️ {self.account_name}: Using GitHub client ID from config")
            else:
                client_id_result = await self.get_auth_client_id(session, headers, "github")
                if client_id_result and client_id_result.get("success"):
                    print(f"ℹ️ {self.account_name}: Got client ID for GitHub: {client_id_result['client_id']}")
                else:
                    error_msg = client_id_result.get("error", "Unknown error")
                    print(f"❌ {self.account_name}: {error_msg}")
                    return False, {"error": "Failed to get GitHub client ID"}

            # 获取 OAuth 认证状态
            auth_state_result = await self.get_auth_state(
                session=session,
                headers=headers,
            )
            if auth_state_result and auth_state_result.get("success"):
                print(f"ℹ️ {self.account_name}: Got auth state for GitHub: {auth_state_result['state']}")
            else:
                error_msg = auth_state_result.get("error", "Unknown error")
                print(f"❌ {self.account_name}: {error_msg}")
                return False, {"error": "Failed to get GitHub auth state"}

            # 生成缓存文件路径
            username_hash = hashlib.sha256(username.encode("utf-8")).hexdigest()[:8]
            cache_file_path = f"{self.storage_state_dir}/github_{username_hash}_storage_state.json"

            from sign_in_with_github import GitHubSignIn

            github = GitHubSignIn(
                account_name=self.account_name,
                provider_config=self.provider_config,
                username=username,
                password=password,
            )

            success, result_data, oauth_browser_headers = await github.signin(
                client_id=client_id_result["client_id"],
                auth_state=auth_state_result.get("state"),
                auth_cookies=auth_state_result.get("cookies", []),
                cache_file_path=cache_file_path
            )
            cache_status = "miss"
            if isinstance(result_data, dict):
                cache_status_value = result_data.get("cache_status")
                if isinstance(cache_status_value, list):
                    cache_status_value = cache_status_value[0] if cache_status_value else None
                if isinstance(cache_status_value, str) and cache_status_value:
                    cache_status = cache_status_value

            # 检查是否成功获取 cookies 和 api_user
            if success and "cookies" in result_data and "api_user" in result_data:
                # 统一调用 check_in_with_cookies 执行签到
                user_cookies = result_data["cookies"]
                api_user = result_data["api_user"]

                # 如果 OAuth 登录返回了 browser_headers，用它更新 common_headers
                updated_headers = common_headers.copy()
                if oauth_browser_headers:
                    print(f"ℹ️ {self.account_name}: Updating headers with OAuth browser fingerprint")
                    updated_headers.update(oauth_browser_headers)

                merged_cookies = {**bypass_cookies, **user_cookies}
                check_success, user_info = await self.check_in_with_cookies(
                    merged_cookies, updated_headers, api_user, impersonate
                )
                if isinstance(user_info, dict):
                    user_info["cache_status"] = cache_status
                return check_success, user_info
            elif success and "code" in result_data and "state" in result_data:
                # 收到 OAuth code，通过 HTTP 调用回调接口获取 api_user
                print(f"ℹ️ {self.account_name}: Received OAuth code, calling callback API")

                # 构建带参数的回调 URL
                base_url = self.provider_config.get_github_auth_url()
                callback_url = f"{base_url}?{urlencode(result_data, doseq=True)}"
                print(f"ℹ️ {self.account_name}: Callback URL: {callback_url}")
                try:
                    # 将 Camoufox 格式的 cookies 转换为 curl_cffi 格式
                    auth_cookies_list = auth_state_result.get("cookies", [])
                    for cookie_dict in auth_cookies_list:
                        session.cookies.set(cookie_dict["name"], cookie_dict["value"])

                    # 如果 OAuth 登录返回了 browser_headers，用它更新 common_headers
                    updated_headers = common_headers.copy()
                    if oauth_browser_headers:
                        print(f"ℹ️ {self.account_name}: Updating headers with OAuth browser fingerprint")
                        updated_headers.update(oauth_browser_headers)

                    response = session.get(callback_url, headers=updated_headers, timeout=30)

                    if response.status_code == 200:
                        json_data = response_resolve(response, "github_oauth_callback", self.account_name)
                        if json_data and json_data.get("success"):
                            user_data = json_data.get("data", {})
                            api_user = user_data.get("id")

                            if api_user:
                                print(f"✅ {self.account_name}: Got api_user from callback: {api_user}")

                                # 提取 cookies
                                user_cookies = {}
                                for cookie in response.cookies.jar:
                                    user_cookies[cookie.name] = cookie.value

                                print(
                                    f"ℹ️ {self.account_name}: Extracted {len(user_cookies)} user cookies: {list(user_cookies.keys())}"
                                )
                                merged_cookies = {**bypass_cookies, **user_cookies}
                                check_success, user_info = await self.check_in_with_cookies(
                                    merged_cookies, updated_headers, api_user, impersonate
                                )
                                if isinstance(user_info, dict):
                                    user_info["cache_status"] = cache_status
                                return check_success, user_info
                            else:
                                print(f"❌ {self.account_name}: No user ID in callback response")
                                return False, {"error": "No user ID in OAuth callback response"}
                        else:
                            error_msg = json_data.get("message", "Unknown error") if json_data else "Invalid response"
                            print(f"❌ {self.account_name}: OAuth callback failed: {error_msg}")
                            return False, {"error": f"OAuth callback failed: {error_msg}"}
                    else:
                        print(f"❌ {self.account_name}: OAuth callback HTTP {response.status_code}")
                        return False, {"error": f"OAuth callback HTTP {response.status_code}"}
                except Exception as callback_err:
                    print(f"❌ {self.account_name}: Error calling OAuth callback: {callback_err}")
                    return False, {"error": f"OAuth callback error: {callback_err}"}
            else:
                # 返回错误信息
                return False, result_data

        except Exception as e:
            print(f"❌ {self.account_name}: Error occurred during check-in process - {e}")
            return False, {"error": "GitHub check-in process error"}
        finally:
            session.close()

    async def check_in_with_linuxdo(
        self,
        username: str,
        password: str,
        bypass_cookies: dict,
        common_headers: dict,
        oauth_retry: int = 0,
    ) -> tuple[bool, dict]:
        """使用 Linux.do 账号执行签到操作

        Args:
            username: Linux.do 用户名
            password: Linux.do 密码
            bypass_cookies: bypass cookies
            common_headers: 公用请求头（包含 User-Agent 和可能的 Client Hints）
        """
        print(
            f"ℹ️ {self.account_name}: Executing check-in with Linux.do account (using proxy: {'true' if self.http_proxy_config else 'false'})"
        )

        # 根据 User-Agent 自动推断 impersonate 值，在 Session 上设置全局 impersonate
        user_agent = common_headers.get("User-Agent", "")
        impersonate = get_curl_cffi_impersonate(user_agent)
        
        session = curl_requests.Session(impersonate=impersonate, proxy=self.http_proxy_config, timeout=30)
        if impersonate:
            print(f"ℹ️ {self.account_name}: Using curl_cffi Session with impersonate={impersonate}")
        
        try:
            session.cookies.update(bypass_cookies)

            # 使用传入的公用请求头，并添加动态头部
            headers = common_headers.copy()
            headers[self.provider_config.api_user_key] = "-1"
            headers["Referer"] = self.provider_config.get_login_url()
            headers["Origin"] = self.provider_config.origin

            # 获取 OAuth 客户端 ID
            # 仅从 provider 配置读取，不做动态获取
            client_id = str(self.provider_config.linuxdo_client_id or "").strip()
            if client_id:
                client_id_result = {
                    "success": True,
                    "client_id": client_id,
                }
                print(f"ℹ️ {self.account_name}: Using Linux.do client ID from config")
            else:
                client_id_result = await self.get_auth_client_id(session, headers, "linuxdo")
                if client_id_result and client_id_result.get("success"):
                    dynamic_client_id = str(client_id_result.get("client_id", "")).strip()
                    if not dynamic_client_id:
                        print(f"❌ {self.account_name}: Linux.do client_id is empty from status API")
                        return False, {"error": "Failed to get Linux.do client ID"}
                    client_id_result = {
                        "success": True,
                        "client_id": dynamic_client_id,
                    }
                    print(f"ℹ️ {self.account_name}: Got client ID for Linux.do: {dynamic_client_id}")
                else:
                    error_msg = client_id_result.get("error", "Unknown error")
                    print(f"❌ {self.account_name}: {error_msg}")
                    return False, {"error": "Failed to get Linux.do client ID"}

            # 获取 OAuth 认证状态
            auth_state_result = await self.get_auth_state(
                session=session,
                headers=headers,
            )
            if auth_state_result and auth_state_result.get("success"):
                print(f"ℹ️ {self.account_name}: Got auth state for Linux.do: {auth_state_result['state']}")
            else:
                error_msg = auth_state_result.get("error", "Unknown error")
                print(f"❌ {self.account_name}: {error_msg}")
                return False, {"error": "Failed to get Linux.do auth state"}

            # 生成缓存文件路径
            username_hash = hashlib.sha256(username.encode("utf-8")).hexdigest()[:8]
            cache_file_path = f"{self.storage_state_dir}/linuxdo_{username_hash}_storage_state.json"

            from sign_in_with_linuxdo import LinuxDoSignIn

            linuxdo = LinuxDoSignIn(
                account_name=self.account_name,
                provider_config=self.provider_config,
                username=username,
                password=password,
            )

            browser_auth_cookies = list(auth_state_result.get("cookies", []))
            if bypass_cookies:
                provider_domain = urlparse(self.provider_config.origin).netloc
                secure_default = self.provider_config.origin.startswith("https://")
                existing_cookie_names = {
                    cookie.get("name") for cookie in browser_auth_cookies if cookie.get("name")
                }
                for cookie_name, cookie_value in bypass_cookies.items():
                    if not cookie_name or cookie_value is None or cookie_name in existing_cookie_names:
                        continue
                    browser_auth_cookies.append(
                        {
                            "name": cookie_name,
                            "value": str(cookie_value),
                            "domain": provider_domain,
                            "path": "/",
                            "secure": secure_default,
                            "httpOnly": False,
                            "sameSite": "Lax",
                        }
                    )
                    existing_cookie_names.add(cookie_name)

            success, result_data, oauth_browser_headers = await linuxdo.signin(
                client_id=client_id_result["client_id"],
                auth_state=auth_state_result["state"],
                auth_cookies=browser_auth_cookies,
                cache_file_path=cache_file_path
            )
            cache_status = "miss"
            if isinstance(result_data, dict):
                cache_status_value = result_data.get("cache_status")
                if isinstance(cache_status_value, list):
                    cache_status_value = cache_status_value[0] if cache_status_value else None
                if isinstance(cache_status_value, str) and cache_status_value:
                    cache_status = cache_status_value

            error_text = ""
            if isinstance(result_data, dict):
                error_text = str(result_data.get("error", ""))
            retryable_oauth_error = ("no code in callback" in error_text.lower()) or ("expired=true" in error_text.lower())
            if (not success) and oauth_retry < 1 and retryable_oauth_error:
                print(
                    f"⚠️ {self.account_name}: Linux.do OAuth callback lost "
                    f"(retry={oauth_retry + 1}/1), restarting Linux.do flow once"
                )
                return await self.check_in_with_linuxdo(
                    username=username,
                    password=password,
                    bypass_cookies=bypass_cookies,
                    common_headers=common_headers,
                    oauth_retry=oauth_retry + 1,
                )

            # 检查是否成功获取 cookies 和 api_user
            if success and "cookies" in result_data and "api_user" in result_data:
                # 统一调用 check_in_with_cookies 执行签到
                user_cookies = result_data["cookies"]
                api_user = result_data["api_user"]

                # 如果 OAuth 登录返回了 browser_headers，用它更新 common_headers
                updated_headers = common_headers.copy()
                if oauth_browser_headers:
                    print(f"ℹ️ {self.account_name}: Updating headers with OAuth browser fingerprint")
                    updated_headers.update(oauth_browser_headers)

                merged_cookies = {**bypass_cookies, **user_cookies}
                check_success, user_info = await self.check_in_with_cookies(
                    merged_cookies, updated_headers, api_user, impersonate
                )
                if isinstance(user_info, dict):
                    user_info["cache_status"] = cache_status
                return check_success, user_info
            elif success and "code" in result_data and "state" in result_data:
                # 收到 OAuth code，通过 HTTP 调用回调接口获取 api_user
                print(f"ℹ️ {self.account_name}: Received OAuth code, calling callback API")

                # 构建带参数的回调 URL
                base_url = self.provider_config.get_linuxdo_auth_url()
                callback_url = f"{base_url}?{urlencode(result_data, doseq=True)}"
                print(f"ℹ️ {self.account_name}: Callback URL: {callback_url}")
                try:
                    # 将 Camoufox 格式的 cookies 转换为 curl_cffi 格式
                    auth_cookies_list = auth_state_result.get("cookies", [])
                    for cookie_dict in auth_cookies_list:
                        session.cookies.set(cookie_dict["name"], cookie_dict["value"])

                    # 如果 OAuth 登录返回了 browser_headers，用它更新 common_headers
                    updated_headers = common_headers.copy()
                    if oauth_browser_headers:
                        print(f"ℹ️ {self.account_name}: Updating headers with OAuth browser fingerprint")
                        updated_headers.update(oauth_browser_headers)

                    response = session.get(callback_url, headers=updated_headers, timeout=30)

                    if response.status_code == 200:
                        json_data = response_resolve(response, "linuxdo_oauth_callback", self.account_name)
                        if json_data and json_data.get("success"):
                            user_data = json_data.get("data", {})
                            api_user = user_data.get("id")

                            if api_user:
                                print(f"✅ {self.account_name}: Got api_user from callback: {api_user}")

                                # 提取 cookies
                                user_cookies = {}
                                for cookie in response.cookies.jar:
                                    user_cookies[cookie.name] = cookie.value

                                print(
                                    f"ℹ️ {self.account_name}: Extracted {len(user_cookies)} user cookies: {list(user_cookies.keys())}"
                                )
                                merged_cookies = {**bypass_cookies, **user_cookies}
                                check_success, user_info = await self.check_in_with_cookies(
                                    merged_cookies, updated_headers, api_user, impersonate
                                )
                                if isinstance(user_info, dict):
                                    user_info["cache_status"] = cache_status
                                return check_success, user_info
                            else:
                                print(f"❌ {self.account_name}: No user ID in callback response")
                                return False, {"error": "No user ID in OAuth callback response"}
                        else:
                            error_msg = json_data.get("message", "Unknown error") if json_data else "Invalid response"
                            print(f"❌ {self.account_name}: OAuth callback failed: {error_msg}")
                            return False, {"error": f"OAuth callback failed: {error_msg}"}
                    else:
                        print(f"❌ {self.account_name}: OAuth callback HTTP {response.status_code}")
                        return False, {"error": f"OAuth callback HTTP {response.status_code}"}
                except Exception as callback_err:
                    print(f"❌ {self.account_name}: Error calling OAuth callback: {callback_err}")
                    return False, {"error": f"OAuth callback error: {callback_err}"}
            else:
                # 返回错误信息
                return False, result_data

        except Exception as e:
            print(f"❌ {self.account_name}: Error occurred during check-in process - {e}")
            return False, {"error": "Linux.do check-in process error"}
        finally:
            session.close()

    async def execute(self) -> list[tuple[str, bool, dict | None]]:
        """为单个账号执行签到操作，支持多种认证方式"""
        print(f"\n\n⏳ Starting to process {self.account_name}")

        bypass_cookies = {}
        browser_headers = None  # 浏览器指纹头部信息
        
        if self.provider_config.needs_waf_cookies():
            waf_cookies = await self.get_waf_cookies_with_browser()
            if waf_cookies:
                bypass_cookies = waf_cookies
                print(f"✅ {self.account_name}: WAF cookies obtained")
            else:
                print(f"⚠️ {self.account_name}: Unable to get WAF cookies, continuing with empty cookies")

        elif self.provider_config.needs_cf_clearance():
            # 直接调用公共模块的 get_cf_clearance 函数
            try:
                cf_result = await get_cf_clearance(
                    url=self.provider_config.get_login_url(),
                    account_name=self.account_name,
                    proxy_config=self.camoufox_proxy_config,
                )
                
                if cf_result[0]:
                    bypass_cookies = cf_result[0]
                    print(f"✅ {self.account_name}: Cloudflare cookies obtained")
                else:
                    print(f"⚠️ {self.account_name}: Unable to get Cloudflare cookies, continuing with empty cookies")

                # 因为 Cloudflare 验证需要一致的浏览器指纹
                if cf_result[1]:
                    browser_headers = cf_result[1]
                    print(f"✅ {self.account_name}: Cloudflare fingerprint headers obtained")
            except Exception as e:
                print(f"❌ {self.account_name}: Error occurred while getting cf_clearance cookie: {e}")
                print(f"⚠️ {self.account_name}: Continuing with empty cookies")
        else:
            print(f"ℹ️ {self.account_name}: Bypass not required, using user cookies directly")

        # 生成公用请求头（只生成一次 User-Agent，整个签到流程保持一致）
        # 注意：Referer 和 Origin 不在这里设置，由各个签到方法根据实际请求动态设置
        if browser_headers:
            # 如果有浏览器指纹头部（来自 cf_clearance 获取），使用它
            common_headers = {
                "Accept": "application/json, text/plain, */*",
                "Accept-Language": "en,en-US;q=0.9,zh;q=0.8,en-CN;q=0.7,zh-CN;q=0.6",
                "Cache-Control": "no-store",
                "Pragma": "no-cache",
                "User-Agent": browser_headers.get("User-Agent", get_random_user_agent()),
                "sec-fetch-dest": "empty",
                "sec-fetch-mode": "cors",
                "sec-fetch-site": "same-origin",
            }
            
            # 只有当 browser_headers 中包含 sec-ch-ua 时才添加 Client Hints 头部
            # Firefox 浏览器不支持 Client Hints，所以 browser_headers 中不会有这些头部
            # 如果强行添加会导致 Cloudflare 检测到指纹不一致而返回 403
            if "sec-ch-ua" in browser_headers:
                common_headers.update({
                    "sec-ch-ua": browser_headers.get("sec-ch-ua", ""),
                    "sec-ch-ua-mobile": browser_headers.get("sec-ch-ua-mobile", "?0"),
                    "sec-ch-ua-platform": browser_headers.get("sec-ch-ua-platform", ""),
                    "sec-ch-ua-platform-version": browser_headers.get("sec-ch-ua-platform-version", ""),
                    "sec-ch-ua-arch": browser_headers.get("sec-ch-ua-arch", ""),
                    "sec-ch-ua-bitness": browser_headers.get("sec-ch-ua-bitness", ""),
                    "sec-ch-ua-full-version": browser_headers.get("sec-ch-ua-full-version", ""),
                    "sec-ch-ua-full-version-list": browser_headers.get("sec-ch-ua-full-version-list", ""),
                    "sec-ch-ua-model": browser_headers.get("sec-ch-ua-model", '""'),
                })
                print(f"ℹ️ {self.account_name}: Using browser fingerprint headers (with Client Hints)")
            else:
                print(f"ℹ️ {self.account_name}: Using browser fingerprint headers (Firefox, no Client Hints)")
        else:
            # 没有浏览器指纹，生成一次随机 User-Agent 并在整个流程中使用
            random_ua = get_random_user_agent()
            common_headers = {
                "Accept": "application/json, text/plain, */*",
                "Accept-Language": "en,en-US;q=0.9,zh;q=0.8,en-CN;q=0.7,zh-CN;q=0.6",
                "Cache-Control": "no-store",
                "Pragma": "no-cache",
                "User-Agent": random_ua,
                "sec-fetch-dest": "empty",
                "sec-fetch-mode": "cors",
                "sec-fetch-site": "same-origin",
            }
            print(f"ℹ️ {self.account_name}: Using random User-Agent (generated once)")

        # 解析账号配置
        cookie_accounts = self.account_config.cookies
        users = self.account_config.users
        github_accounts = self.account_config.github  # 现在是 List[OAuthAccountConfig] 类型
        linuxdo_accounts = self.account_config.linux_do  # 现在是 List[OAuthAccountConfig] 类型
        results = []

        # 尝试 cookies 认证
        if cookie_accounts:
            for idx, cookie_account in enumerate(cookie_accounts):
                account_label = f"cookies[{idx}]" if len(cookie_accounts) > 1 else "cookies"
                print(f"\nℹ️ {self.account_name}: Trying cookies authentication ({account_label})")
                try:
                    user_cookies = parse_cookies(cookie_account.cookies)
                    if not user_cookies:
                        print(f"❌ {self.account_name}: Invalid cookies format")
                        results.append((account_label, False, {"error": "Invalid cookies format"}))
                        continue

                    api_user = cookie_account.api_user
                    if not api_user:
                        print(f"❌ {self.account_name}: API user identifier not found for cookies")
                        results.append((account_label, False, {"error": "API user identifier not found"}))
                        continue

                    all_cookies = {**bypass_cookies, **user_cookies}
                    success, user_info = await self.check_in_with_cookies(all_cookies, common_headers, api_user)
                    if success:
                        print(f"✅ {self.account_name}: Cookies authentication successful")
                        results.append((account_label, True, user_info))
                    else:
                        print(f"❌ {self.account_name}: Cookies authentication failed")
                        results.append((account_label, False, user_info))
                except Exception as e:
                    print(f"❌ {self.account_name}: Cookies authentication error: {e}")
                    results.append((account_label, False, {"error": str(e)}))

        # 尝试密码认证（用户名/邮箱 + 密码，支持 user 数组）
        if users:
            for idx, user_account in enumerate(users):
                account_label = f"user[{idx}]" if len(users) > 1 else "user"
                print(f"\nℹ️ {self.account_name}: Trying password authentication ({mask_username(user_account.username)})")
                try:
                    username = user_account.username
                    password = user_account.password
                    if not username or not password:
                        print(f"❌ {self.account_name}: Incomplete password account information")
                        results.append((account_label, False, {"error": "Incomplete password account information"}))
                    else:
                        success, user_info = await self.sign_in_with_password(
                            username,
                            password,
                            bypass_cookies,
                            common_headers,
                        )
                        if success:
                            print(
                                f"✅ {self.account_name}: Password authentication successful "
                                f"({mask_username(user_account.username)})"
                            )
                            results.append((account_label, True, user_info))
                        else:
                            print(
                                f"❌ {self.account_name}: Password authentication failed "
                                f"({mask_username(user_account.username)})"
                            )
                            results.append((account_label, False, user_info))
                except Exception as e:
                    print(
                        f"❌ {self.account_name}: Password authentication error "
                        f"({mask_username(user_account.username)}): {e}"
                    )
                    results.append((account_label, False, {"error": str(e)}))

        # 尝试 GitHub 认证（支持多个账号）
        if github_accounts:
            for idx, github_account in enumerate(github_accounts):
                account_label = f"github[{idx}]" if len(github_accounts) > 1 else "github"
                print(f"\nℹ️ {self.account_name}: Trying GitHub authentication ({mask_username(github_account.username)})")
                try:
                    username = github_account.username
                    password = github_account.password
                    if not username or not password:
                        print(f"❌ {self.account_name}: Incomplete GitHub account information")
                        results.append((account_label, False, {"error": "Incomplete GitHub account information"}))
                    else:
                        # 使用 GitHub 账号执行签到，传入公用请求头
                        success, user_info = await self.check_in_with_github(
                            username, password, bypass_cookies, common_headers
                        )
                        if success:
                            print(f"✅ {self.account_name}: GitHub authentication successful ({mask_username(github_account.username)})")
                            results.append((account_label, True, user_info))
                        else:
                            print(f"❌ {self.account_name}: GitHub authentication failed ({mask_username(github_account.username)})")
                            results.append((account_label, False, user_info))
                except Exception as e:
                    print(f"❌ {self.account_name}: GitHub authentication error ({mask_username(github_account.username)}): {e}")
                    results.append((account_label, False, {"error": str(e)}))

        # 尝试 Linux.do 认证（支持多个账号）
        if linuxdo_accounts:
            for idx, linuxdo_account in enumerate(linuxdo_accounts):
                account_label = f"linux.do[{idx}]" if len(linuxdo_accounts) > 1 else "linux.do"
                print(f"\nℹ️ {self.account_name}: Trying Linux.do authentication ({mask_username(linuxdo_account.username)})")
                try:
                    username = linuxdo_account.username
                    password = linuxdo_account.password
                    if not username or not password:
                        print(f"❌ {self.account_name}: Incomplete Linux.do account information")
                        results.append((account_label, False, {"error": "Incomplete Linux.do account information"}))
                    else:
                        # 使用 Linux.do 账号执行签到，传入公用请求头
                        success, user_info = await self.check_in_with_linuxdo(
                            username,
                            password,
                            bypass_cookies,
                            common_headers,
                        )
                        if success:
                            print(f"✅ {self.account_name}: Linux.do authentication successful ({mask_username(linuxdo_account.username)})")
                            results.append((account_label, True, user_info))
                        else:
                            print(f"❌ {self.account_name}: Linux.do authentication failed ({mask_username(linuxdo_account.username)})")
                            results.append((account_label, False, user_info))
                except Exception as e:
                    print(f"❌ {self.account_name}: Linux.do authentication error ({mask_username(linuxdo_account.username)}): {e}")
                    results.append((account_label, False, {"error": str(e)}))

        if not results:
            print(f"❌ {self.account_name}: No valid authentication method found in configuration")
            return []

        # 输出最终结果
        print(f"\n📋 {self.account_name} authentication results:")
        successful_count = 0
        for auth_method, success, user_info in results:
            status = "✅" if success else "❌"
            print(f"  {status} {auth_method} authentication")
            if success:
                successful_count += 1

        print(f"\n🎯 {self.account_name}: {successful_count}/{len(results)} authentication methods successful")

        return results

   
