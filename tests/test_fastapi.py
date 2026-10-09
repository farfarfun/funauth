"""`funauth.contrib.fastapi` 的测试：真起一个 app、真打 HTTP 请求。

这里不 mock FastAPI。要验的东西恰好都在「被 FastAPI 跑起来之后」才成立 ——
依赖注解能不能解析、`dependency_overrides` 能不能穿到注册开关上、cookie 会不会
在请求之间带上、门禁是 401 还是 403。拿 mock 替掉框架，这些全测不到。

注意：本文件**刻意不写** `from __future__ import annotations`。handler 签名里
`session: SessionDep` 用的是运行时变量，PEP 563 把注解变成字符串之后 FastAPI
解析不出来 —— 这和 `contrib/fastapi.py` 自己不写那一行是同一个原因。
"""

from collections.abc import AsyncIterator
from typing import Annotated, Any

import pytest
import pytest_asyncio
from fastapi import APIRouter, Depends, FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from starlette.middleware.sessions import SessionMiddleware

from funauth import Accounts, UserRole
from funauth.contrib.fastapi import UserOut, make_auth_router, make_user_deps

from .conftest import InviteCode, User


#: 测试用的注册开关。`dependency_overrides` 的 key 必须是这个函数对象本身。
def registration_enabled() -> bool:
    return True


class Harness:
    """一个装好的 app + 它的几个可覆盖依赖。"""

    def __init__(self, app: FastAPI, accounts: Accounts, auth_router: APIRouter) -> None:
        self.app = app
        self.accounts = accounts
        #: 单独留一份。`include_router` 之后 `app.routes` 里是包装对象，
        #: 想看「挂了哪几条路由」还得回到 router 本身。
        self.auth_router = auth_router

    def client(self) -> AsyncClient:
        """每个 client 一套独立 cookie —— 用来模拟两个不同的浏览器。"""
        return AsyncClient(transport=ASGITransport(app=self.app), base_url="http://test")


def build_harness(engine, *, with_invite: bool = True) -> Harness:
    """拼出一个最小宿主：会话依赖 + SessionMiddleware + 两道门 + auth 路由。

    这同时是宿主侧接法的可执行文档 —— README 里那段示例代码在这里真跑一遍。
    """
    accounts = Accounts(
        user_model=User,
        invite_model=InviteCode if with_invite else None,
    )
    maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async def get_session() -> AsyncIterator[AsyncSession]:
        async with maker() as s:
            try:
                yield s
            except Exception:
                # 宿主负责事务边界。注册时抛 409 要靠这里把扣掉的名额退回去。
                await s.rollback()
                raise

    session_dep = Annotated[AsyncSession, Depends(get_session)]
    enabled_dep = Annotated[bool, Depends(registration_enabled)]

    app = FastAPI()
    app.add_middleware(SessionMiddleware, secret_key="test-secret")

    guards = make_user_deps(accounts=accounts, session_dep=session_dep)

    @app.get("/protected")
    async def protected(user: guards.current_user) -> dict[str, Any]:
        return {"username": user.username}

    @app.get("/ops")
    async def ops(user: guards.admin_user) -> dict[str, Any]:
        return {"username": user.username}

    auth_router = make_auth_router(
        accounts=accounts,
        session_dep=session_dep,
        registration_enabled_dep=enabled_dep,
    )
    app.include_router(auth_router)
    return Harness(app, accounts, auth_router)


@pytest_asyncio.fixture
async def harness(engine) -> Harness:
    return build_harness(engine)


@pytest_asyncio.fixture
async def admin(session, harness) -> User:
    return await harness.accounts.create_user(session, "boss", "pw123456", UserRole.ADMIN)


@pytest_asyncio.fixture
async def guest(session, harness) -> User:
    return await harness.accounts.create_user(session, "visitor", "pw123456", UserRole.GUEST)


class TestLogin:
    async def test_login_then_me_then_logout(self, harness, admin):
        async with harness.client() as c:
            r = await c.post("/auth/login", json={"username": "boss", "password": "pw123456"})
            assert r.status_code == 200
            assert r.json() == {"id": str(admin.id), "username": "boss", "role": "admin"}

            # cookie 带上了，/me 认得出是谁
            assert (await c.get("/auth/me")).json()["username"] == "boss"

            assert (await c.post("/auth/logout")).status_code == 204
            assert (await c.get("/auth/me")).json() is None

    async def test_me_without_login_is_null_not_401(self, harness):
        """前端启动时无条件打这个接口。回 401 会在控制台刷一片红。"""
        async with harness.client() as c:
            r = await c.get("/auth/me")
            assert r.status_code == 200
            assert r.json() is None

    async def test_failures_share_one_message(self, harness, admin, session):
        """密码错 / 用户不存在 / 账号停用，三种 401 文案必须一致。

        拆开任何一种，这个接口就成了用户名枚举器。
        """
        async with harness.client() as c:
            wrong_pw = await c.post(
                "/auth/login", json={"username": "boss", "password": "nope-nope"}
            )
            no_such = await c.post("/auth/login", json={"username": "ghost", "password": "pw1234"})

            await harness.accounts.set_active(session, "boss", False)
            disabled = await c.post(
                "/auth/login", json={"username": "boss", "password": "pw123456"}
            )

        assert {r.status_code for r in (wrong_pw, no_such, disabled)} == {401}
        assert len({r.json()["detail"] for r in (wrong_pw, no_such, disabled)}) == 1

    async def test_sessions_are_per_client(self, harness, admin):
        """一个浏览器登录不会让另一个也登录上 —— 会话在 cookie 里，不是进程里。"""
        async with harness.client() as logged_in, harness.client() as anonymous:
            await logged_in.post("/auth/login", json={"username": "boss", "password": "pw123456"})
            assert (await logged_in.get("/auth/me")).json() is not None
            assert (await anonymous.get("/auth/me")).json() is None


class TestGates:
    async def test_site_gate_blocks_anonymous(self, harness):
        async with harness.client() as c:
            r = await c.get("/protected")
            assert r.status_code == 401

    async def test_site_gate_lets_guest_in(self, harness, guest):
        async with harness.client() as c:
            await c.post("/auth/login", json={"username": "visitor", "password": "pw123456"})
            r = await c.get("/protected")
            assert r.status_code == 200
            assert r.json() == {"username": "visitor"}

    async def test_admin_gate_rejects_guest_with_403(self, harness, guest):
        """403 而不是 404：这个人已经登录了，只是权限不够。"""
        async with harness.client() as c:
            await c.post("/auth/login", json={"username": "visitor", "password": "pw123456"})
            r = await c.get("/ops")
            assert r.status_code == 403

    async def test_admin_gate_rejects_anonymous_with_401(self, harness):
        """没登录的人撞运维接口拿 401，不是 403 —— 他该先去登录。"""
        async with harness.client() as c:
            assert (await c.get("/ops")).status_code == 401

    async def test_admin_gate_lets_admin_in(self, harness, admin):
        async with harness.client() as c:
            await c.post("/auth/login", json={"username": "boss", "password": "pw123456"})
            assert (await c.get("/ops")).status_code == 200

    async def test_disabling_invalidates_live_cookie(self, harness, admin, session):
        """停用立刻生效，而不是等 cookie 过期。

        会话里只存 user_id、角色每个请求重查库，就是为了这个。
        """
        async with harness.client() as c:
            await c.post("/auth/login", json={"username": "boss", "password": "pw123456"})
            assert (await c.get("/protected")).status_code == 200

            await harness.accounts.set_active(session, "boss", False)

            r = await c.get("/protected")
            assert r.status_code == 401
            assert r.json()["detail"] == "登录已失效，请重新登录"
            # 失效的会话被清掉了，下个请求不用再白查一次库
            assert (await c.get("/auth/me")).json() is None

    async def test_demoting_takes_effect_immediately(self, harness, admin, session):
        async with harness.client() as c:
            await c.post("/auth/login", json={"username": "boss", "password": "pw123456"})
            assert (await c.get("/ops")).status_code == 200

            admin.role = UserRole.GUEST
            await session.commit()

            assert (await c.get("/ops")).status_code == 403


class TestRegister:
    async def test_register_with_valid_code_logs_in_as_guest(self, harness, session):
        code = await harness.accounts.issue_invite(session)
        async with harness.client() as c:
            r = await c.post(
                "/auth/register",
                json={"username": "newbie", "password": "pw123456", "invite_code": code.code},
            )
            assert r.status_code == 201
            assert r.json()["role"] == "guest"
            # 注册完直接进站，不用再登一次
            assert (await c.get("/auth/me")).json()["username"] == "newbie"

    async def test_role_cannot_be_chosen_by_the_caller(self, harness, session):
        """出参模型里有 role，但入参里没有 —— 多传的字段不该把人变成管理员。"""
        code = await harness.accounts.issue_invite(session)
        async with harness.client() as c:
            r = await c.post(
                "/auth/register",
                json={
                    "username": "sneaky",
                    "password": "pw123456",
                    "invite_code": code.code,
                    "role": "admin",
                },
            )
            assert r.status_code == 201
            assert r.json()["role"] == "guest"
            assert (await c.get("/ops")).status_code == 403

    async def test_bad_codes_share_one_message(self, harness, session):
        """用完的码和不存在的码必须是同一句话，否则这接口能探测码存不存在。"""
        code = await harness.accounts.issue_invite(session, max_uses=1)
        async with harness.client() as c:
            first = await c.post(
                "/auth/register",
                json={"username": "first", "password": "pw123456", "invite_code": code.code},
            )
            assert first.status_code == 201

            exhausted = await c.post(
                "/auth/register",
                json={"username": "second", "password": "pw123456", "invite_code": code.code},
            )
            missing = await c.post(
                "/auth/register",
                json={"username": "third", "password": "pw123456", "invite_code": "NOSUCHCD"},
            )

        assert {r.status_code for r in (exhausted, missing)} == {400}
        assert len({r.json()["detail"] for r in (exhausted, missing)}) == 1

    async def test_username_taken_is_409_and_refunds_the_slot(self, harness, session, guest):
        """撞用户名返回 409，而且扣掉的那一次名额要退回来。

        退回靠的是宿主会话依赖里的 rollback —— handler 抛的 HTTPException 会一路
        传到那个 `except` 里。这条测试同时在验那个契约。
        """
        code = await harness.accounts.issue_invite(session, max_uses=1)
        async with harness.client() as c:
            r = await c.post(
                "/auth/register",
                json={"username": "visitor", "password": "pw123456", "invite_code": code.code},
            )
            assert r.status_code == 409

            # 名额没被白扣，同一张码还能正常兑
            ok = await c.post(
                "/auth/register",
                json={"username": "fresh", "password": "pw123456", "invite_code": code.code},
            )
            assert ok.status_code == 201

    async def test_short_password_is_422_not_201(self, harness, session):
        code = await harness.accounts.issue_invite(session)
        async with harness.client() as c:
            r = await c.post(
                "/auth/register",
                json={"username": "newbie", "password": "123", "invite_code": code.code},
            )
            assert r.status_code == 422

    async def test_missing_invite_code_is_422(self, harness):
        """邀请码是必填 —— 少传一个字段不能变成「无码注册」。"""
        async with harness.client() as c:
            r = await c.post("/auth/register", json={"username": "newbie", "password": "pw123456"})
            assert r.status_code == 422


class TestRegistrationSwitch:
    async def test_config_reports_the_switch(self, harness):
        async with harness.client() as c:
            assert (await c.get("/auth/config")).json() == {"registration_enabled": True}

    async def test_override_reaches_both_endpoints(self, harness, session):
        """开关必须是个 FastAPI 依赖，不能是捕获来的 bool 或闭包。

        宿主在测试里靠 `dependency_overrides` 关掉注册。捕获值会绕过覆盖，于是
        这个开关在测试里根本改不动 —— 这条测试就是钉住这件事。
        """
        code = await harness.accounts.issue_invite(session)
        harness.app.dependency_overrides[registration_enabled] = lambda: False
        try:
            async with harness.client() as c:
                assert (await c.get("/auth/config")).json() == {"registration_enabled": False}
                r = await c.post(
                    "/auth/register",
                    json={"username": "newbie", "password": "pw123456", "invite_code": code.code},
                )
                assert r.status_code == 403
        finally:
            harness.app.dependency_overrides.clear()

    async def test_switch_defaults_to_open_when_not_given(self, engine, session):
        accounts = Accounts(user_model=User, invite_model=InviteCode)
        code = await accounts.issue_invite(session)

        app = FastAPI()
        app.add_middleware(SessionMiddleware, secret_key="test-secret")
        maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

        async def get_session() -> AsyncIterator[AsyncSession]:
            async with maker() as s:
                yield s

        app.include_router(
            make_auth_router(
                accounts=accounts, session_dep=Annotated[AsyncSession, Depends(get_session)]
            )
        )
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            assert (await c.get("/auth/config")).json() == {"registration_enabled": True}
            r = await c.post(
                "/auth/register",
                json={"username": "newbie", "password": "pw123456", "invite_code": code.code},
            )
            assert r.status_code == 201


class TestShape:
    async def test_no_register_route_without_invite_model(self, engine):
        """没有邀请码表就没有自助注册这条路。

        挂一个必然 500 的端点出去不如根本不挂 —— OpenAPI 里也就不会骗人。
        """
        harness = build_harness(engine, with_invite=False)
        paths = {r.path for r in harness.auth_router.routes}
        assert "/auth/login" in paths
        assert "/auth/register" not in paths
        # OpenAPI 里也不该出现，否则前端生成的 client 会多一个必然失败的方法
        assert "/auth/register" not in harness.app.openapi()["paths"]

    async def test_register_route_present_with_invite_model(self, harness):
        assert "/auth/register" in {r.path for r in harness.auth_router.routes}
        assert "/auth/register" in harness.app.openapi()["paths"]

    async def test_custom_user_out_is_honored(self, engine, session):
        class RichUserOut(UserOut):
            is_active: bool

        accounts = Accounts(user_model=User, invite_model=InviteCode)
        user = await accounts.create_user(session, "boss", "pw123456", UserRole.ADMIN)

        app = FastAPI()
        app.add_middleware(SessionMiddleware, secret_key="test-secret")
        maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

        async def get_session() -> AsyncIterator[AsyncSession]:
            async with maker() as s:
                yield s

        app.include_router(
            make_auth_router(
                accounts=accounts,
                session_dep=Annotated[AsyncSession, Depends(get_session)],
                user_out=RichUserOut,
            )
        )
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.post("/auth/login", json={"username": "boss", "password": "pw123456"})
            assert r.json() == {
                "id": str(user.id),
                "username": "boss",
                "role": "admin",
                "is_active": True,
            }

    async def test_prefix_and_tags_are_configurable(self, engine):
        accounts = Accounts(user_model=User)

        async def get_session() -> AsyncIterator[AsyncSession]:  # pragma: no cover - 不会被调用
            raise AssertionError("不该走到这里")
            yield

        router = make_auth_router(
            accounts=accounts,
            session_dep=Annotated[AsyncSession, Depends(get_session)],
            prefix="/identity",
            tags=["身份"],
        )
        assert {r.path for r in router.routes} == {
            "/identity/config",
            "/identity/login",
            "/identity/logout",
            "/identity/me",
        }
        assert all(r.tags == ["身份"] for r in router.routes)


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/auth/config"),
        ("GET", "/auth/me"),
        ("POST", "/auth/login"),
        ("POST", "/auth/logout"),
        ("POST", "/auth/register"),
    ],
)
async def test_auth_routes_are_public(harness, method, path):
    """auth 这组路由不能挂门禁 —— 否则没登录的人连登录接口都打不开。

    只验「没被门禁提前拦掉」：空 body 换来 422、密码不对换来 401 都是另一回事，
    这里看的是匿名请求能不能走到 handler 里。
    """
    async with harness.client() as c:
        r = await c.request(method, path, json={})
        assert r.status_code in (200, 201, 204, 400, 422), r.status_code
