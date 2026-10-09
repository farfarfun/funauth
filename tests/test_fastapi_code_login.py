"""`make_code_login_router` 的测试：真起 app、真打请求。

和 `test_fastapi.py` 一样刻意**不写** `from __future__ import annotations` ——
handler 签名里的依赖注解是运行时变量，PEP 563 把它变成字符串之后 FastAPI 解析
不出来。
"""

from collections.abc import AsyncIterator
from typing import Annotated

import pytest
import pytest_asyncio
from fastapi import Depends, FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from starlette.middleware.sessions import SessionMiddleware

from funauth import Accounts, AuthProvider
from funauth.contrib.fastapi import make_auth_router, make_code_login_router, make_user_deps

from .conftest import Identity, InviteCode, User, VerificationCode

TARGET = "someone@example.com"


def registration_enabled() -> bool:
    return True


class Mailbox:
    """假的发送通道。记下发出去的 `(标识, 验证码)`，可以让它失败。"""

    def __init__(self):
        self.sent = []
        self.explode = False

    async def send(self, target: str, code: str) -> None:
        if self.explode:
            raise RuntimeError("SMTP 挂了")
        self.sent.append((target, code))

    @property
    def last_code(self) -> str:
        return self.sent[-1][1]


class CodeHarness:
    def __init__(self, app, accounts, mailbox, router):
        self.app = app
        self.accounts = accounts
        self.mailbox = mailbox
        self.router = router

    def client(self) -> AsyncClient:
        return AsyncClient(transport=ASGITransport(app=self.app), base_url="http://test")

    async def get_code(self, client, target: str = TARGET) -> str:
        """走一遍真实流程拿到验证码：打 /code，再从假邮箱里把它读出来。"""
        r = await client.post("/auth/email/code", json={"target": target})
        assert r.status_code == 204, r.text
        return self.mailbox.last_code


def build_code_harness(engine, *, min_interval_seconds=0) -> CodeHarness:
    """最小宿主：会话依赖 + SessionMiddleware + auth 路由 + 验证码路由。

    这同时是 README 里那段接法的可执行版本。
    """
    accounts = Accounts(
        user_model=User,
        invite_model=InviteCode,
        identity_model=Identity,
        challenge_model=VerificationCode,
    )
    maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async def get_session() -> AsyncIterator[AsyncSession]:
        async with maker() as s:
            try:
                yield s
            except Exception:
                await s.rollback()
                raise

    session_dep = Annotated[AsyncSession, Depends(get_session)]
    enabled_dep = Annotated[bool, Depends(registration_enabled)]

    app = FastAPI()
    app.add_middleware(SessionMiddleware, secret_key="test-secret")

    guards = make_user_deps(accounts=accounts, session_dep=session_dep)

    @app.get("/protected")
    async def protected(user: guards.current_user) -> dict:
        return {"username": user.username}

    app.include_router(
        make_auth_router(
            accounts=accounts, session_dep=session_dep, registration_enabled_dep=enabled_dep
        )
    )
    mailbox = Mailbox()
    router = make_code_login_router(
        accounts=accounts,
        session_dep=session_dep,
        sender=mailbox.send,
        provider=AuthProvider.EMAIL,
        registration_enabled_dep=enabled_dep,
        min_interval_seconds=min_interval_seconds,
    )
    app.include_router(router)
    return CodeHarness(app, accounts, mailbox, router)


@pytest_asyncio.fixture
async def code_harness(engine) -> CodeHarness:
    return build_code_harness(engine)


class TestShape:
    async def test_routes_are_namespaced_by_provider(self, code_harness):
        """邮箱和短信各挂一套，路径不能撞。"""
        assert {r.path for r in code_harness.router.routes} == {
            "/auth/email/code",
            "/auth/email/login",
        }

    async def test_both_providers_can_coexist(self, engine):
        accounts = Accounts(
            user_model=User, identity_model=Identity, challenge_model=VerificationCode
        )

        async def noop(target, code):
            pass

        async def get_session() -> AsyncIterator[AsyncSession]:  # pragma: no cover
            raise AssertionError("不该走到这里")
            yield

        dep = Annotated[AsyncSession, Depends(get_session)]
        paths = set()
        for provider in (AuthProvider.EMAIL, AuthProvider.PHONE):
            r = make_code_login_router(
                accounts=accounts, session_dep=dep, sender=noop, provider=provider
            )
            paths |= {route.path for route in r.routes}

        assert paths == {
            "/auth/email/code",
            "/auth/email/login",
            "/auth/phone/code",
            "/auth/phone/login",
        }

    async def test_the_plaintext_code_is_never_in_a_response(self, code_harness):
        """明文只走发送通道，绝不能出现在 HTTP 响应里。

        回给前端就等于公开所有人的验证码 —— 谁都能替别人登录。
        """
        async with code_harness.client() as c:
            r = await c.post("/auth/email/code", json={"target": TARGET})
            assert r.status_code == 204
            assert not r.content, "204 不该有 body"

            code = code_harness.mailbox.last_code
            assert code not in r.text


class TestRequestCode:
    async def test_code_reaches_the_sender(self, code_harness):
        async with code_harness.client() as c:
            await c.post("/auth/email/code", json={"target": TARGET})

        target, code = code_harness.mailbox.sent[-1]
        assert target == TARGET
        assert code.isdigit() and len(code) == 6

    async def test_target_is_normalized_before_sending(self, code_harness):
        """发给规整后的地址，和库里存的那个保持一致。"""
        async with code_harness.client() as c:
            await c.post("/auth/email/code", json={"target": "  Me@Example.COM "})

        assert code_harness.mailbox.sent[-1][0] == "me@example.com"

    async def test_unregistered_target_still_gets_a_code(self, code_harness):
        """没注册过的邮箱也照发 —— 验证码登录本身就兼注册。

        「没注册就不发」等于把「这个邮箱注册过没有」做成一个公开查询接口。
        """
        async with code_harness.client() as c:
            r = await c.post("/auth/email/code", json={"target": "brand-new@example.com"})
            assert r.status_code == 204
        assert code_harness.mailbox.sent

    async def test_throttled_resend_is_429_with_retry_after(self, engine):
        harness = build_code_harness(engine, min_interval_seconds=60)
        async with harness.client() as c:
            assert (await c.post("/auth/email/code", json={"target": TARGET})).status_code == 204

            r = await c.post("/auth/email/code", json={"target": TARGET})
            assert r.status_code == 429
            assert r.headers["Retry-After"] == "60", "前端要靠这个头做倒计时"

    async def test_send_failure_is_502_and_does_not_burn_the_throttle_window(self, engine):
        """发送失败要把刚签发的记录删掉。

        不删的话用户既没收到码、又要被限频挡 60 秒 —— 而这完全是我们这边的
        故障，不该让他等。
        """
        harness = build_code_harness(engine, min_interval_seconds=60)
        harness.mailbox.explode = True

        async with harness.client() as c:
            assert (await c.post("/auth/email/code", json={"target": TARGET})).status_code == 502

            # 立刻重试不该被限频挡住
            harness.mailbox.explode = False
            r = await c.post("/auth/email/code", json={"target": TARGET})
            assert r.status_code == 204, "上一次失败的签发把限频窗口白占了"

    async def test_oversized_target_is_422(self, code_harness):
        async with code_harness.client() as c:
            r = await c.post("/auth/email/code", json={"target": "a" * 500 + "@example.com"})
            assert r.status_code == 422


class TestCodeLogin:
    async def test_first_login_creates_an_account_and_a_session(self, code_harness, session):
        async with code_harness.client() as c:
            code = await code_harness.get_code(c)

            r = await c.post("/auth/email/login", json={"target": TARGET, "code": code})
            assert r.status_code == 200
            assert r.json()["role"] == "guest", "这条路只能产出 guest"

            # 登录态已经建立 —— 不用再登一次
            assert (await c.get("/auth/me")).json()["username"] == r.json()["username"]
            assert (await c.get("/protected")).status_code == 200

        assert await session.scalar(select(func.count()).select_from(User)) == 1

    async def test_second_login_reuses_the_account(self, code_harness, session):
        async with code_harness.client() as c:
            first = await c.post(
                "/auth/email/login",
                json={"target": TARGET, "code": await code_harness.get_code(c)},
            )
            await c.post("/auth/logout")
            second = await c.post(
                "/auth/email/login",
                json={"target": TARGET, "code": await code_harness.get_code(c)},
            )

        assert first.json()["id"] == second.json()["id"]
        assert await session.scalar(select(func.count()).select_from(User)) == 1

    async def test_case_variants_land_on_one_account(self, code_harness, session):
        """`Me@Example.com` 和 `me@example.com` 是同一个人。

        不规整的后果不是报错，是悄悄多出一个账号 —— 用户会以为数据丢了。
        """
        async with code_harness.client() as c:
            await c.post(
                "/auth/email/login",
                json={
                    "target": "Me@Example.com",
                    "code": await code_harness.get_code(c, "Me@Example.com"),
                },
            )
            await c.post("/auth/logout")
            await c.post(
                "/auth/email/login",
                json={
                    "target": "me@EXAMPLE.com",
                    "code": await code_harness.get_code(c, "me@example.com"),
                },
            )

        assert await session.scalar(select(func.count()).select_from(User)) == 1

    async def test_wrong_code_is_400_and_creates_nothing(self, code_harness, session):
        async with code_harness.client() as c:
            real = await code_harness.get_code(c)
            wrong = "000000" if real != "000000" else "111111"

            r = await c.post("/auth/email/login", json={"target": TARGET, "code": wrong})
            assert r.status_code == 400

        assert await session.scalar(select(func.count()).select_from(User)) == 0

    async def test_code_is_single_use(self, code_harness):
        async with code_harness.client() as c:
            code = await code_harness.get_code(c)
            assert (
                await c.post("/auth/email/login", json={"target": TARGET, "code": code})
            ).status_code == 200

            await c.post("/auth/logout")
            again = await c.post("/auth/email/login", json={"target": TARGET, "code": code})
            assert again.status_code == 400, "一次性的码被用了第二次"

    async def test_failure_reasons_share_one_message(self, code_harness):
        """码不对 / 没发过码，两种 400 文案必须一致。"""
        async with code_harness.client() as c:
            real = await code_harness.get_code(c)
            wrong = "000000" if real != "000000" else "111111"

            bad_code = await c.post("/auth/email/login", json={"target": TARGET, "code": wrong})
            no_code = await c.post(
                "/auth/email/login", json={"target": "never-asked@example.com", "code": "123456"}
            )

        assert {r.status_code for r in (bad_code, no_code)} == {400}
        assert len({r.json()["detail"] for r in (bad_code, no_code)}) == 1

    async def test_brute_force_is_capped(self, code_harness):
        """连续猜错 5 次之后，连正确的码也不认了。

        这条同时在验「试错计数活过了 rollback」—— 每次 400 都会触发宿主会话
        依赖里的 rollback，计数要是跟着回滚，这个上限根本不存在。
        """
        async with code_harness.client() as c:
            real = await code_harness.get_code(c)
            wrong = "000000" if real != "000000" else "111111"

            for _ in range(5):
                r = await c.post("/auth/email/login", json={"target": TARGET, "code": wrong})
                assert r.status_code == 400

            blocked = await c.post("/auth/email/login", json={"target": TARGET, "code": real})
            assert blocked.status_code == 400, "试错超限之后这张码应该已经废了"

    async def test_login_is_rejected_when_signup_is_off_for_a_new_target(self, code_harness):
        """注册关着时，没绑过的标识拿 403 —— 而且码照样发得出去。"""
        code_harness.app.dependency_overrides[registration_enabled] = lambda: False
        try:
            async with code_harness.client() as c:
                # 发码不受影响，否则这个接口就成了「这个邮箱注册过没有」的探测器
                code = await code_harness.get_code(c)
                r = await c.post("/auth/email/login", json={"target": TARGET, "code": code})
                assert r.status_code == 403
        finally:
            code_harness.app.dependency_overrides.clear()

    async def test_existing_user_still_logs_in_when_signup_is_off(self, code_harness):
        """关掉注册只该挡住新人，不该把老用户一起锁在门外。"""
        async with code_harness.client() as c:
            await c.post(
                "/auth/email/login",
                json={"target": TARGET, "code": await code_harness.get_code(c)},
            )
            await c.post("/auth/logout")

            code_harness.app.dependency_overrides[registration_enabled] = lambda: False
            try:
                r = await c.post(
                    "/auth/email/login",
                    json={"target": TARGET, "code": await code_harness.get_code(c)},
                )
                assert r.status_code == 200
            finally:
                code_harness.app.dependency_overrides.clear()

    async def test_disabled_account_gets_403(self, code_harness, session):
        async with code_harness.client() as c:
            r = await c.post(
                "/auth/email/login",
                json={"target": TARGET, "code": await code_harness.get_code(c)},
            )
            username = r.json()["username"]
            await c.post("/auth/logout")

            await code_harness.accounts.set_active(session, username, False)

            blocked = await c.post(
                "/auth/email/login",
                json={"target": TARGET, "code": await code_harness.get_code(c)},
            )
            assert blocked.status_code == 403


@pytest.mark.parametrize(
    ("method", "path"),
    [("POST", "/auth/email/code"), ("POST", "/auth/email/login")],
)
async def test_code_routes_are_public(code_harness, method, path):
    """这两条不能挂门禁 —— 否则没登录的人连登录接口都打不开。"""
    async with code_harness.client() as c:
        r = await c.request(method, path, json={})
        assert r.status_code in (200, 204, 400, 422), r.status_code
