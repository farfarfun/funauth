"""密码登录、角色、邀请码、建号、账号管理。"""

from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.dialects import postgresql

from funauth import (
    BadCredentials,
    InviteUnusable,
    LastAdmin,
    PasswordNotSet,
    PermissionDenied,
    UsernameTaken,
    UserRole,
    describe_invite_status,
    generate_code,
    hash_password,
)
from funauth.models.types import utcnow
from funauth.services.password import BAD_CREDENTIALS

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


class TestSetRole:
    async def test_promote_and_demote(self, session, accounts) -> None:
        await accounts.create_user(session, "boss", "pw", UserRole.ADMIN)
        await accounts.create_user(session, "reader", "pw", UserRole.GUEST)

        assert await accounts.set_role(session, "reader", UserRole.ADMIN) is True
        assert (await accounts.get_by_username(session, "reader")).role is UserRole.ADMIN

        # 现在有两个管理员了，降一个下去是允许的
        assert await accounts.set_role(session, "boss", UserRole.GUEST) is True
        assert (await accounts.get_by_username(session, "boss")).role is UserRole.GUEST

    async def test_unknown_user_returns_false(self, session, accounts) -> None:
        assert await accounts.set_role(session, "nobody", UserRole.ADMIN) is False


async def _demote_boss(accounts, session, **kwargs) -> None:
    await accounts.set_role(session, "boss", UserRole.GUEST, **kwargs)


async def _disable_boss(accounts, session, **kwargs) -> None:
    await accounts.set_active(session, "boss", False, **kwargs)


class TestLastAdminGuard:
    """「最后一个在用的管理员」不许降级，也不许停用。

    降完 / 停完就没人进得去后台了，补救只能去命令行 —— 而点「降为访客」的人
    正在整理名单，完全不会想到这一层。两个方法行为必须一致：拦住降级却放过
    停用，等于把同一个坑留了另一个入口。下面每条都对两个方法各跑一遍。
    """

    @pytest.fixture
    async def sole_admin(self, session, accounts):
        return await accounts.create_user(session, "boss", "pw", UserRole.ADMIN)

    @pytest.fixture(params=[_demote_boss, _disable_boss], ids=["set_role", "set_active"])
    def remove_admin(self, request):
        return request.param

    async def test_blocked(self, session, accounts, sole_admin, remove_admin) -> None:
        with pytest.raises(LastAdmin):
            await remove_admin(accounts, session)

        await session.rollback()
        boss = await accounts.get_by_username(session, "boss")
        assert boss.role is UserRole.ADMIN and boss.is_active is True

    async def test_escape_hatch(self, session, accounts, sole_admin, remove_admin) -> None:
        """明知故犯的出口：迁移脚本、拆站、宿主另有后门入口。"""
        await remove_admin(accounts, session, allow_last_admin=True)
        boss = await accounts.get_by_username(session, "boss")
        assert (boss.role, boss.is_active) != (UserRole.ADMIN, True)

    async def test_allowed_when_another_active_admin_remains(
        self, session, accounts, sole_admin, remove_admin
    ) -> None:
        await accounts.create_user(session, "second", "pw", UserRole.ADMIN)
        await remove_admin(accounts, session)

    async def test_a_disabled_admin_does_not_count(
        self, session, accounts, sole_admin, remove_admin
    ) -> None:
        """停用的管理员登不进来，不能拿他给自己壮胆。"""
        await accounts.create_user(session, "retired", "pw", UserRole.ADMIN)
        await accounts.set_active(session, "retired", False)

        with pytest.raises(LastAdmin):
            await remove_admin(accounts, session)

    async def test_guest_is_never_guarded(self, session, accounts) -> None:
        """一个管理员都没有的站里停用访客，不该撞上「最后一个管理员」。"""
        await accounts.create_user(session, "reader", "pw", UserRole.GUEST)

        assert await accounts.set_active(session, "reader", False) is True
        assert await accounts.set_role(session, "reader", UserRole.GUEST) is True

    async def test_already_inactive_admin_can_be_demoted(self, session, accounts) -> None:
        """清理一个本来就停用的管理员，不会让情况更糟，所以不许拦。

        拦了的后果是：一旦在用管理员归零，连打扫卫生都做不了。
        """
        await accounts.create_user(session, "retired", "pw", UserRole.ADMIN)
        await accounts.set_active(session, "retired", False, allow_last_admin=True)

        assert await accounts.set_role(session, "retired", UserRole.GUEST) is True

    async def test_recovery_paths_are_never_guarded(self, session, accounts) -> None:
        """锁死之后的三条救场路径必须畅通：启用、提升、以及把管理员设成管理员。"""
        await accounts.create_user(session, "retired", "pw", UserRole.ADMIN)
        await accounts.create_user(session, "reader", "pw", UserRole.GUEST)
        await accounts.set_active(session, "retired", False, allow_last_admin=True)
        assert await accounts.count_users(session, role=UserRole.ADMIN, is_active=True) == 0

        assert await accounts.set_role(session, "reader", UserRole.ADMIN) is True
        assert await accounts.set_active(session, "retired", True) is True
        assert await accounts.set_role(session, "retired", UserRole.ADMIN) is True


class TestSetRoleMany:
    async def test_counts_and_dedupes(self, session, accounts) -> None:
        for name in ["a", "b"]:
            await accounts.create_user(session, name, "pw", UserRole.GUEST)

        # 重复的名字只算一次，查无此人的不算 —— 管理页上那几行可能刚被别人改过
        assert await accounts.set_role_many(session, ["a", "a", "b", "ghost"], UserRole.ADMIN) == 2
        assert await accounts.count_users(session, role=UserRole.ADMIN) == 2

    async def test_empty_list_is_a_no_op(self, session, accounts) -> None:
        assert await accounts.set_role_many(session, [], UserRole.ADMIN) == 0

    async def test_the_guard_looks_at_the_whole_batch(self, session, accounts) -> None:
        """一次降掉仅剩的两个管理员要被拦住，而且**一行都不许改**。

        逐行判会让这两个人互相「证明还有人在」，于是一起被降掉，一声不吭。
        而中途抛异常会留下半批改完的脏会话 —— 本包的规矩是回滚归调用方，
        把那种东西甩给他是陷阱。所以判定必须在动手之前、对整批一起做。
        """
        for name in ["one", "two"]:
            await accounts.create_user(session, name, "pw", UserRole.ADMIN)

        with pytest.raises(LastAdmin):
            await accounts.set_role_many(session, ["one", "two"], UserRole.GUEST)

        assert await accounts.count_users(session, role=UserRole.ADMIN, is_active=True) == 2

    async def test_demoting_all_but_one_is_fine(self, session, accounts) -> None:
        for name in ["one", "two"]:
            await accounts.create_user(session, name, "pw", UserRole.ADMIN)

        assert await accounts.set_role_many(session, ["one"], UserRole.GUEST) == 1
        assert await accounts.count_users(session, role=UserRole.ADMIN, is_active=True) == 1


class TestSetUsername:
    async def test_rename(self, session, accounts) -> None:
        await accounts.create_user(session, "wechat_3f9c1d2a", "pw", UserRole.GUEST)

        assert await accounts.set_username(session, "wechat_3f9c1d2a", "alice") is True
        assert await accounts.authenticate(session, "alice", "pw")
        assert await accounts.get_by_username(session, "wechat_3f9c1d2a") is None

    async def test_collision_is_refused_and_changes_nothing(self, session, accounts) -> None:
        await accounts.create_user(session, "alice", "pw", UserRole.GUEST)
        await accounts.create_user(session, "bob", "pw", UserRole.GUEST)

        with pytest.raises(UsernameTaken):
            await accounts.set_username(session, "bob", "alice")
        assert (await accounts.get_by_username(session, "bob")).username == "bob"

    async def test_renaming_to_the_same_name_is_a_no_op(self, session, accounts) -> None:
        await accounts.create_user(session, "alice", "pw", UserRole.GUEST)
        assert await accounts.set_username(session, "alice", "alice") is True

    async def test_unknown_user_returns_false(self, session, accounts) -> None:
        assert await accounts.set_username(session, "nobody", "whoever") is False


class TestChangePassword:
    async def test_happy_path(self, session, accounts) -> None:
        await accounts.create_user(session, "u", "old", UserRole.GUEST)

        user = await accounts.change_password(session, "u", "old", "new")
        assert user.username == "u"
        assert await accounts.authenticate(session, "u", "new")
        with pytest.raises(BadCredentials):
            await accounts.authenticate(session, "u", "old")

    async def test_wrong_old_password_changes_nothing(self, session, accounts) -> None:
        await accounts.create_user(session, "u", "old", UserRole.GUEST)

        with pytest.raises(BadCredentials):
            await accounts.change_password(session, "u", "nope", "new")
        assert await accounts.authenticate(session, "u", "old")

    async def test_unknown_and_disabled_share_the_login_message(self, session, accounts) -> None:
        await accounts.create_user(session, "off", "old", UserRole.GUEST)
        await accounts.set_active(session, "off", False)

        messages = set()
        for username in ["off", "ghost"]:
            with pytest.raises(BadCredentials) as err:
                await accounts.change_password(session, username, "old", "new")
            messages.add(str(err.value))
        assert messages == {BAD_CREDENTIALS}

    async def test_passwordless_account_gets_a_useful_error(self, session, accounts) -> None:
        """微信 / 验证码注册的账号没有旧密码可校验，这里**刻意说实话**。

        调用方是从会话里拿到用户名的，他已经证明了自己就是这个账号；回一句
        「用户名或密码不正确」只会让他对着表单反复试一个从来不存在的旧密码。
        """
        user = await accounts.create_user(session, "wechat_3f9c1d2a", None, UserRole.GUEST)
        assert user.password_hash is None

        with pytest.raises(PasswordNotSet) as err:
            await accounts.change_password(session, "wechat_3f9c1d2a", "whatever", "new")
        assert str(err.value) != BAD_CREDENTIALS


class TestUserListing:
    @pytest.fixture
    async def crowd(self, session, accounts):
        await accounts.create_user(session, "Alice", "pw", UserRole.ADMIN)
        await accounts.create_user(session, "bob", "pw", UserRole.GUEST)
        await accounts.create_user(session, "carol", "pw", UserRole.GUEST)
        await accounts.create_user(session, "wechat_3f9c1d2a", None, UserRole.GUEST)
        await accounts.set_active(session, "carol", False)

    async def test_filters(self, session, accounts, crowd) -> None:
        admins = await accounts.list_users(session, role=UserRole.ADMIN)
        assert [u.username for u in admins] == ["Alice"]

        disabled = await accounts.list_users(session, is_active=False)
        assert [u.username for u in disabled] == ["carol"]

        # is_active=False 是一个过滤条件，不是「这项没传」
        assert await accounts.count_users(session, is_active=False) == 1
        assert await accounts.count_users(session, is_active=True) == 3
        assert await accounts.count_users(session) == 4

    async def test_keyword_is_case_insensitive(self, session, accounts, crowd) -> None:
        """SQLite 的 LIKE 对 ASCII 不区分大小写而 PostgreSQL 区分。

        用 `like` 的话这条在测试里绿、在生产上搜不着 —— 本包承诺两个库行为一致。
        """
        assert [u.username for u in await accounts.list_users(session, keyword="ALI")] == ["Alice"]

    async def test_wildcards_in_the_keyword_are_literal(self, session, accounts, crowd) -> None:
        """`_` 和 `%` 必须当字面量。

        不转义的话自动生成的用户名（`wechat_3f9c1d2a` 这种全带下划线）一搜就乱
        套，而一个 `%` 就能匹配全表 —— 分页器拿着「总数 4」渲染一个空列表。
        """
        assert await accounts.count_users(session, keyword="%") == 0
        assert await accounts.count_users(session, keyword="b_b") == 0
        assert await accounts.count_users(session, keyword="wechat_") == 1
        # 反斜杠要先换，不然后面补出来的转义符会被二次转义，PostgreSQL 直接报错
        assert await accounts.count_users(session, keyword="a\\b") == 0

    async def test_keyword_compiles_to_an_escaped_ilike(self, accounts) -> None:
        """盯住发出去的 SQL：行为测试在 SQLite 上对 `like` 也会绿。"""
        condition = accounts._user_where(role=None, is_active=None, keyword="a_b")[0]
        sql = str(condition.compile(dialect=postgresql.dialect()))
        assert "ILIKE" in sql.upper(), "大小写敏感性会在 PostgreSQL 上和测试不一致"
        assert "ESCAPE" in sql.upper(), "没有 ESCAPE，转义出来的反斜杠自己会变成字面量"

    async def test_pagination(self, session, accounts, crowd) -> None:
        names = [u.username for u in await accounts.list_users(session)]
        assert names == ["Alice", "bob", "carol", "wechat_3f9c1d2a"]

        page = await accounts.list_users(session, offset=1, limit=2)
        assert [u.username for u in page] == ["bob", "carol"]

        # 翻过头给空页，总数照旧 —— 分页器据此退回最后一页
        assert await accounts.list_users(session, offset=99, limit=2) == []
        assert await accounts.count_users(session) == 4

    async def test_limit_zero_means_zero_rows(self, session, accounts, crowd) -> None:
        """`None` 才是「不限」，`0` 是「别给我」。真值判断会把两者搞混。"""
        assert await accounts.list_users(session, limit=0) == []
        assert len(await accounts.list_users(session, limit=None)) == 4

    async def test_count_matches_the_list_for_the_same_filters(
        self, session, accounts, crowd
    ) -> None:
        for filters in [{}, {"role": UserRole.GUEST}, {"keyword": "o"}, {"is_active": True}]:
            listed = await accounts.list_users(session, **filters)
            assert await accounts.count_users(session, **filters) == len(listed), filters
