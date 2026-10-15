"""`make_admin_router` 的测试：真起一个 app、真打 HTTP 请求。

和 `test_fastapi.py` 同一套路数，也**刻意不写** `from __future__ import
annotations` —— handler 签名里 `session: SessionDep`、`user_id: user_id_type`
用的都是运行时变量，PEP 563 把注解变成字符串之后 FastAPI 解析不出来。

这里有一个默认夹具看不见的坑，所以单独配了一个 `expire_on_commit=True` 的
harness：服务层提交之后会话里的对象就 expire 了，这时候再序列化它会触发一次
懒加载，而在异步会话里那是 `MissingGreenlet`，也就是一个 500。
`tests/conftest.py` 用的是 `expire_on_commit=False`，照它测的话这个 bug 要等
上线才出现。
"""

import uuid
from collections.abc import AsyncIterator
from typing import Annotated, Any

import pytest
import pytest_asyncio
from fastapi import Depends, FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from starlette.middleware.sessions import SessionMiddleware

from funauth import Accounts, UserRole
from funauth.contrib.fastapi import UserOut, make_admin_router, make_auth_router, make_user_deps

from .conftest import User

PASSWORD = "pw123456"


class AdminHarness:
    def __init__(self, app, accounts, router):
        self.app = app
        self.accounts = accounts
        self.router = router

    def client(self) -> AsyncClient:
        return AsyncClient(transport=ASGITransport(app=self.app), base_url="http://test")

    async def login(self, client, username: str) -> None:
        r = await client.post("/auth/login", json={"username": username, "password": PASSWORD})
        assert r.status_code == 200, r.text


def build_admin_harness(engine, *, expire_on_commit=True, **router_kwargs):
    """拼出一个最小宿主：会话依赖 + 两道门 + auth 路由 + 管理路由。

    这同时是 README 里那段接法的可执行版本。
    """
    accounts = Accounts(user_model=User)
    maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=expire_on_commit)

    async def get_session() -> AsyncIterator[AsyncSession]:
        async with maker() as s:
            try:
                yield s
            except Exception:
                await s.rollback()
                raise

    session_dep = Annotated[AsyncSession, Depends(get_session)]

    app = FastAPI()
    app.add_middleware(SessionMiddleware, secret_key="test-secret")
    guards = make_user_deps(accounts=accounts, session_dep=session_dep)

    app.include_router(make_auth_router(accounts=accounts, session_dep=session_dep))
    router = make_admin_router(
        accounts=accounts, session_dep=session_dep, guards=guards, **router_kwargs
    )
    app.include_router(router)
    return AdminHarness(app, accounts, router)


@pytest_asyncio.fixture
async def admin_harness(engine) -> AdminHarness:
    return build_admin_harness(engine)


@pytest_asyncio.fixture
async def boss(session, admin_harness) -> User:
    return await admin_harness.accounts.create_user(session, "boss", PASSWORD, UserRole.ADMIN)


@pytest_asyncio.fixture
async def visitor(session, admin_harness) -> User:
    return await admin_harness.accounts.create_user(session, "visitor", PASSWORD, UserRole.GUEST)


class TestGate:
    """整组路由都要 ADMIN。这是另一条接线（`guards` 而不是裸依赖），单独钉一遍。"""

    @pytest.mark.parametrize("path", ["/admin/users"])
    async def test_anonymous_gets_401(self, admin_harness, path) -> None:
        async with admin_harness.client() as c:
            assert (await c.get(path)).status_code == 401

    async def test_guest_gets_403(self, admin_harness, visitor) -> None:
        async with admin_harness.client() as c:
            await admin_harness.login(c, "visitor")
            assert (await c.get("/admin/users")).status_code == 403

            r = await c.patch(f"/admin/users/{visitor.id}/role", json={"role": "admin"})
            assert r.status_code == 403, "访客不该能把自己提成管理员"

    async def test_admin_gets_in(self, admin_harness, boss) -> None:
        async with admin_harness.client() as c:
            await admin_harness.login(c, "boss")
            assert (await c.get("/admin/users")).status_code == 200


class TestList:
    async def test_page_shape_and_filters(self, session, admin_harness, boss, visitor) -> None:
        await admin_harness.accounts.create_user(session, "carol", PASSWORD, UserRole.GUEST)

        async with admin_harness.client() as c:
            await admin_harness.login(c, "boss")

            body = (await c.get("/admin/users")).json()
            assert body["total"] == 3
            assert [u["username"] for u in body["items"]] == ["boss", "carol", "visitor"]
            # 管理表格要渲染启停开关，所以默认出参比 `UserOut` 多这一个字段
            assert body["items"][0]["is_active"] is True

            page = (await c.get("/admin/users", params={"offset": 1, "limit": 1})).json()
            assert [u["username"] for u in page["items"]] == ["carol"]
            assert page["total"] == 3, "total 是命中总数，不该被 limit 削掉"

            filtered = (await c.get("/admin/users", params={"role": "admin"})).json()
            assert [u["username"] for u in filtered["items"]] == ["boss"]

            found = (await c.get("/admin/users", params={"keyword": "ISIT"})).json()
            assert [u["username"] for u in found["items"]] == ["visitor"]

    async def test_limit_is_capped(self, admin_harness, boss) -> None:
        """一次拉全表在账号多了之后是个慢查询加一个大响应，上限写死在包里。"""
        async with admin_harness.client() as c:
            await admin_harness.login(c, "boss")
            assert (await c.get("/admin/users", params={"limit": 10_000})).status_code == 422

    async def test_custom_user_out_flows_into_items(self, engine, session) -> None:
        class SlimUserOut(UserOut):
            pass

        harness = build_admin_harness(engine, user_out=SlimUserOut)
        await harness.accounts.create_user(session, "boss", PASSWORD, UserRole.ADMIN)

        async with harness.client() as c:
            await harness.login(c, "boss")
            body = (await c.get("/admin/users")).json()
            assert "is_active" not in body["items"][0], "出参该换成宿主给的那个"


class TestPatch:
    async def test_promote_then_demote(self, admin_harness, boss, visitor) -> None:
        async with admin_harness.client() as c:
            await admin_harness.login(c, "boss")

            r = await c.patch(f"/admin/users/{visitor.id}/role", json={"role": "admin"})
            assert r.status_code == 200
            assert r.json()["role"] == "admin", "改完要回新状态，管理表格直接拿它重渲染"

            r = await c.patch(f"/admin/users/{visitor.id}/role", json={"role": "guest"})
            assert r.json()["role"] == "guest"

    async def test_disable_then_enable(self, admin_harness, boss, visitor) -> None:
        async with admin_harness.client() as c:
            await admin_harness.login(c, "boss")

            r = await c.patch(f"/admin/users/{visitor.id}/active", json={"is_active": False})
            assert r.status_code == 200 and r.json()["is_active"] is False

            r = await c.patch(f"/admin/users/{visitor.id}/active", json={"is_active": True})
            assert r.json()["is_active"] is True

    async def test_unknown_user_is_404(self, admin_harness, boss) -> None:
        async with admin_harness.client() as c:
            await admin_harness.login(c, "boss")
            r = await c.patch(f"/admin/users/{uuid.uuid4()}/role", json={"role": "guest"})
            assert r.status_code == 404

    async def test_cannot_demote_or_disable_yourself(self, admin_harness, boss, visitor) -> None:
        """手滑点到自己那一行的后果是当场失去后台，而这个确认 HTTP 问不出来。"""
        async with admin_harness.client() as c:
            await admin_harness.login(c, "boss")

            assert (
                await c.patch(f"/admin/users/{boss.id}/role", json={"role": "guest"})
            ).status_code == 409
            assert (
                await c.patch(f"/admin/users/{boss.id}/active", json={"is_active": False})
            ).status_code == 409

    async def test_harmless_self_changes_are_allowed(self, admin_harness, boss) -> None:
        """把自己设成管理员、启用自己都是空操作，拦了只会让人困惑。"""
        async with admin_harness.client() as c:
            await admin_harness.login(c, "boss")

            assert (
                await c.patch(f"/admin/users/{boss.id}/role", json={"role": "admin"})
            ).status_code == 200
            assert (
                await c.patch(f"/admin/users/{boss.id}/active", json={"is_active": True})
            ).status_code == 200

    async def test_self_change_can_be_opened_up(self, engine, session) -> None:
        """交接完自己退下的宿主传 `allow_self_change=True`，那时还有 LastAdmin 兜着。"""
        harness = build_admin_harness(engine, allow_self_change=True)
        boss = await harness.accounts.create_user(session, "boss", PASSWORD, UserRole.ADMIN)
        await harness.accounts.create_user(session, "heir", PASSWORD, UserRole.ADMIN)

        async with harness.client() as c:
            await harness.login(c, "boss")
            r = await c.patch(f"/admin/users/{boss.id}/role", json={"role": "guest"})
            assert r.status_code == 200 and r.json()["role"] == "guest"

    async def test_last_admin_is_409(self, admin_harness, boss, visitor) -> None:
        """服务层的护栏在这一层翻译成 409，而**不**提供 `?force=` 这种开关。

        一个点一下就能关掉的安全护栏比没有护栏更糟。
        """
        async with admin_harness.client() as c:
            await admin_harness.login(c, "boss")
            # 换个人来操作，绕开「不能改自己」，直接撞上「最后一个管理员」
            await c.patch(f"/admin/users/{visitor.id}/role", json={"role": "admin"})

        async with admin_harness.client() as c:
            await admin_harness.login(c, "visitor")
            r = await c.patch(f"/admin/users/{boss.id}/role", json={"role": "guest"})
            assert r.status_code == 200, "还有两个管理员，降一个是可以的"

            r = await c.patch(f"/admin/users/{visitor.id}/active", json={"is_active": False})
            assert r.status_code == 409, "visitor 现在是唯一的管理员了"


class TestShape:
    def test_prefix_and_tags_are_configurable(self, engine) -> None:
        harness = build_admin_harness(engine, prefix="/ops", tags=["运维"])
        assert {r.path for r in harness.router.routes} == {
            "/ops/users",
            "/ops/users/{user_id}/role",
            "/ops/users/{user_id}/active",
        }
        assert all(r.tags == ["运维"] for r in harness.router.routes)

    def test_no_delete_route(self, engine) -> None:
        """刻意没有删除端点 —— 停用走 `is_active`，理由见 `UserMixin` 的 docstring。"""
        harness = build_admin_harness(engine)
        assert not [r for r in harness.router.routes if "DELETE" in r.methods]

    def test_two_admin_routers_do_not_collide_in_openapi(self, engine) -> None:
        """分页出参写成泛型而不是 `create_model` 就是为了这个。

        现造的类每次都叫同一个名字，挂两次就在 OpenAPI 里撞 schema 名，而宿主
        拿它生成前端 client。
        """
        harness = build_admin_harness(engine)
        dep = Annotated[Any, Depends(lambda: None)]
        harness.app.include_router(
            make_admin_router(
                accounts=harness.accounts,
                session_dep=dep,
                guards=make_user_deps(accounts=harness.accounts, session_dep=dep),
                prefix="/ops",
            )
        )

        schemas = harness.app.openapi()["components"]["schemas"]
        pages = [name for name in schemas if name.startswith("UserPage")]
        assert pages == ["UserPage_AdminUserOut_"], f"分页出参被造成了好几份：{pages}"
