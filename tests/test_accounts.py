"""密码登录、角色、邀请码、建号。"""

from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.dialects import postgresql

from funauth import (
    BadCredentials,
    InviteUnusable,
    PermissionDenied,
    UsernameTaken,
    UserRole,
    describe_invite_status,
    generate_code,
    hash_password,
)
from funauth.models.types import utcnow

from .conftest import InviteCode, User


def _code(**kwargs) -> InviteCode:
    defaults = {"code": "TESTCODE", "max_uses": 1, "used_count": 0, "is_active": True}
    return InviteCode(**{**defaults, **kwargs})


class TestAuthenticate:
    async def test_happy_path(self, session, accounts) -> None:
        session.add(User(username="u", password_hash=hash_password("pw"), role=UserRole.ADMIN))
        await session.commit()

        user = await accounts.authenticate(session, "u", "pw")
        assert user.role is UserRole.ADMIN

    async def test_all_failures_share_one_message(self, session, accounts) -> None:
        """密码错 / 用户不存在 / 账号停用，三种必须报同一句话。

        分开报的话这个接口就是个用户名枚举器：拿字典刷一遍，回「密码不对」的
        那些就是真实存在的账号。「这个用户被停用了」同样确认了它存在，所以也
        得混进来。
        """
        session.add(User(username="u", password_hash=hash_password("pw")))
        session.add(User(username="off", password_hash=hash_password("pw"), is_active=False))
        await session.commit()

        messages = set()
        for username, password in [("u", "wrong"), ("nobody", "pw"), ("off", "pw")]:
            with pytest.raises(BadCredentials) as err:
                await accounts.authenticate(session, username, password)
            messages.add(str(err.value))
        assert len(messages) == 1, f"三种失败泄漏了区别：{messages}"


class TestRequireRole:
    def test_admin_passes_guest_denied(self, accounts) -> None:
        admin = User(username="a", password_hash="x", role=UserRole.ADMIN)
        guest = User(username="g", password_hash="x", role=UserRole.GUEST)

        accounts.require_role(admin, UserRole.ADMIN)  # 不抛就算过
        with pytest.raises(PermissionDenied):
            accounts.require_role(guest, UserRole.ADMIN)


class TestInvite:
    def test_generated_code_avoids_ambiguous_chars(self) -> None:
        """码要靠人念、靠截图转述，`0O1Il` 认错的概率太高。"""
        codes = "".join(generate_code() for _ in range(200))
        assert not (set(codes) & set("0O1Il")), codes
        assert codes.isalnum() and codes.isupper()

    async def test_consume_is_a_single_guarded_update(self, accounts) -> None:
        """`consume_invite` 必须是**一条**带完整守卫的 UPDATE，不许先查后改。

        先 SELECT 判断再 UPDATE 在并发下会把一张 `max_uses=1` 的码兑出两个
        账号：两个请求都读到 `used_count == 0`、都认为还有名额。这里直接盯住
        发出去的语句 —— 条数变成 2、或者 WHERE 里少了任何一个条件，都说明
        原子性被改坏了，而那种 bug 在单线程测试里是看不出来的。
        """
        captured = []

        class _Result:
            rowcount = 1

        class _Spy:
            async def execute(self, stmt):
                captured.append(stmt)
                return _Result()

        await accounts.consume_invite(_Spy(), "SOMECODE")

        assert len(captured) == 1, "必须一条语句搞定"
        sql = str(captured[0].compile(dialect=postgresql.dialect()))
        assert "UPDATE invite_code" in sql
        assert "used_count < invite_code.max_uses" in sql, "少了名额守卫"
        assert "is_active" in sql, "少了吊销守卫"
        assert "expires_at" in sql, "少了过期守卫"

    async def test_consume_increments_used_count(self, session, accounts) -> None:
        session.add(_code(max_uses=2))
        await session.commit()

        await accounts.consume_invite(session, "TESTCODE")
        await session.commit()
        assert await session.scalar(select(InviteCode.used_count)) == 1

    @pytest.mark.parametrize(
        ("name", "kwargs"),
        [
            ("已用完", {"max_uses": 1, "used_count": 1}),
            ("已吊销", {"is_active": False}),
            ("已过期", {"expires_at": utcnow() - timedelta(days=1)}),
        ],
    )
    async def test_consume_rejects_unusable(self, session, accounts, name, kwargs) -> None:
        session.add(_code(**kwargs))
        await session.commit()

        with pytest.raises(InviteUnusable):
            await accounts.consume_invite(session, "TESTCODE")

    async def test_unusable_reasons_are_indistinguishable(self, session, accounts) -> None:
        """四种拒绝理由共用一句话，否则注册接口就是「码存不存在」的探测器。"""
        session.add(_code(code="USEDUP", max_uses=1, used_count=1))
        session.add(_code(code="REVOKED", is_active=False))
        session.add(_code(code="EXPIRED", expires_at=utcnow() - timedelta(days=1)))
        await session.commit()

        messages = set()
        for code in ["USEDUP", "REVOKED", "EXPIRED", "NOSUCHCODE"]:
            with pytest.raises(InviteUnusable) as err:
                await accounts.consume_invite(session, code)
            messages.add(str(err.value))
        assert len(messages) == 1, f"四种理由泄漏了区别：{messages}"

    async def test_issue_then_revoke(self, session, accounts) -> None:
        code = await accounts.issue_invite(session, max_uses=3, expires_in_days=7, note="给张三")
        assert describe_invite_status(code) == "可用"
        assert code.expires_at is not None

        assert await accounts.revoke_invite(session, code.code) is True
        await session.refresh(code)
        assert describe_invite_status(code) == "已吊销"
        assert await accounts.revoke_invite(session, "NOSUCHCODE") is False

    async def test_list_invites_newest_first(self, session, accounts) -> None:
        first = await accounts.issue_invite(session, note="旧")
        second = await accounts.issue_invite(session, note="新")

        codes = await accounts.list_invites(session)
        assert [c.code for c in codes] == [second.code, first.code]

    def test_describe_status_matches_consume_conditions(self) -> None:
        now = utcnow()
        assert describe_invite_status(_code(is_active=False), now=now) == "已吊销"
        assert (
            describe_invite_status(_code(expires_at=now - timedelta(seconds=1)), now=now)
            == "已过期"
        )
        assert describe_invite_status(_code(used_count=1), now=now) == "已用完"
        assert describe_invite_status(_code(), now=now) == "可用"


class TestRegister:
    async def test_register_yields_guest(self, session, accounts) -> None:
        """注册出来的角色硬编码成 guest —— 邀请码外泄不该等于交出后台。"""
        session.add(_code())
        await session.commit()

        user = await accounts.register_with_invite(session, "newbie", "pw", "TESTCODE")
        assert user.role is UserRole.GUEST
        assert await accounts.authenticate(session, "newbie", "pw")

    async def test_one_shot_code_cannot_be_used_twice(self, session, accounts) -> None:
        session.add(_code())
        await session.commit()

        await accounts.register_with_invite(session, "first", "pw", "TESTCODE")
        with pytest.raises(InviteUnusable):
            await accounts.register_with_invite(session, "second", "pw", "TESTCODE")
        assert await accounts.get_by_username(session, "second") is None

    async def test_duplicate_username_rolls_back_the_use(self, session, accounts) -> None:
        """用户名撞车时扣掉的名额要跟着回滚。

        不然别人手滑输了个重名用户名，这张码就白少一次 —— 而签发的人完全
        看不出为什么。
        """
        session.add(_code(max_uses=2))
        session.add(User(username="taken", password_hash=hash_password("pw")))
        await session.commit()

        with pytest.raises(UsernameTaken):
            await accounts.register_with_invite(session, "taken", "pw", "TESTCODE")

        await session.rollback()
        assert await session.scalar(select(InviteCode.used_count)) == 0

    async def test_create_user_takes_an_explicit_role(self, session, accounts) -> None:
        admin = await accounts.create_user(session, "boss", "pw", UserRole.ADMIN)
        guest = await accounts.create_user(session, "reader", "pw", UserRole.GUEST)
        assert admin.role is UserRole.ADMIN
        assert guest.role is UserRole.GUEST

        with pytest.raises(UsernameTaken):
            await accounts.create_user(session, "boss", "pw", UserRole.ADMIN)

    async def test_default_role_is_guest(self, session, accounts) -> None:
        """漏传角色时往最小权限掉，而不是凭空多一个管理员。"""
        session.add(User(username="u", password_hash=hash_password("pw")))
        await session.commit()

        user = await accounts.get_by_username(session, "u")
        assert user.role is UserRole.GUEST

    async def test_set_password_and_set_active(self, session, accounts) -> None:
        await accounts.create_user(session, "u", "old", UserRole.GUEST)

        assert await accounts.set_password(session, "u", "new") is True
        assert await accounts.authenticate(session, "u", "new")
        assert await accounts.set_password(session, "nobody", "x") is False

        assert await accounts.set_active(session, "u", False) is True
        with pytest.raises(BadCredentials):
            await accounts.authenticate(session, "u", "new")
        assert await accounts.set_active(session, "nobody", True) is False

    async def test_list_users_sorted(self, session, accounts) -> None:
        await accounts.create_user(session, "zoe", "pw", UserRole.GUEST)
        await accounts.create_user(session, "adam", "pw", UserRole.ADMIN)

        assert [u.username for u in await accounts.list_users(session)] == ["adam", "zoe"]
