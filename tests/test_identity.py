"""外部身份：绑定、解绑、凭身份登录。"""

from __future__ import annotations

import pytest
from sqlalchemy import func, select

from funauth import (
    AccountDisabled,
    AuthProvider,
    BadCredentials,
    IdentityTaken,
    LastLoginMethod,
    SignupDisabled,
    UsernameTaken,
    UserRole,
    default_identity_username,
)

from .conftest import Identity, User

WECHAT = AuthProvider.WECHAT
QQ = AuthProvider.QQ


class TestPasswordlessAccounts:
    """外部身份注册出来的账号没有密码。这曾经是个 500。"""

    async def test_create_user_accepts_no_password(self, session, accounts) -> None:
        user = await accounts.create_user(session, "wechat_only", None, UserRole.GUEST)
        assert user.password_hash is None

    async def test_login_attempt_on_passwordless_account_is_not_a_500(
        self, session, accounts
    ) -> None:
        """拿一个无密码账号的用户名去打密码登录，必须是 401 而不是崩。

        `password_hash` 放开 nullable 之后，`verify_password(pw, None)` 会在
        `None.encode()` 上炸 `AttributeError`，而那个异常原来没人 catch ——
        于是只要库里有一个微信账号，拿它的用户名就能把登录接口打成 500。
        """
        await accounts.create_user(session, "wechat_only", None, UserRole.GUEST)

        with pytest.raises(BadCredentials):
            await accounts.authenticate(session, "wechat_only", "anything")

    async def test_empty_password_does_not_become_a_backdoor(self, session, accounts) -> None:
        """空密码不能登进一个无密码账号 —— 空哈希是「没开密码登录」不是「密码是空」。"""
        await accounts.create_user(session, "wechat_only", None, UserRole.GUEST)

        for guess in ["", " ", "None", "null"]:
            with pytest.raises(BadCredentials):
                await accounts.authenticate(session, "wechat_only", guess)

    async def test_passwordless_failure_shares_the_one_message(self, session, accounts) -> None:
        """「这个账号没有密码」也必须混进那一条消息里。

        分开报等于告诉对方「这个账号存在，而且是微信注册的」—— 既确认了账号
        存在，又把他该换哪种方式一起说了。
        """
        await accounts.create_user(session, "pw_user", "realpw", UserRole.GUEST)
        await accounts.create_user(session, "no_pw", None, UserRole.GUEST)

        messages = set()
        for username, password in [("pw_user", "wrong"), ("no_pw", "wrong"), ("ghost", "wrong")]:
            with pytest.raises(BadCredentials) as err:
                await accounts.authenticate(session, username, password)
            messages.add(str(err.value))
        assert len(messages) == 1, f"三种失败泄漏了区别：{messages}"

    async def test_set_password_upgrades_a_passwordless_account(self, session, accounts) -> None:
        """微信注册进来的人之后可以补一个密码，然后两种方式都能用。"""
        user = await accounts.create_user(session, "wechat_only", None, UserRole.GUEST)
        await accounts.link_identity(session, user, WECHAT, "openid-1")

        assert await accounts.set_password(session, "wechat_only", "newpw123") is True
        assert await accounts.authenticate(session, "wechat_only", "newpw123")


class TestLoginWithIdentity:
    async def test_first_scan_creates_an_account(self, session, accounts) -> None:
        user, created = await accounts.login_with_identity(
            session, WECHAT, "openid-1", display_name="张三"
        )
        assert created is True
        assert user.role is UserRole.GUEST, "外部身份注册出来的只能是 guest"
        assert user.password_hash is None
        assert user.username.startswith("wechat_")

    async def test_second_scan_reuses_the_same_account(self, session, accounts) -> None:
        first, created_first = await accounts.login_with_identity(session, WECHAT, "openid-1")
        second, created_second = await accounts.login_with_identity(session, WECHAT, "openid-1")

        assert created_first is True
        assert created_second is False
        assert first.id == second.id
        assert await session.scalar(select(func.count()).select_from(User)) == 1

    async def test_different_openids_are_different_people(self, session, accounts) -> None:
        a, _ = await accounts.login_with_identity(session, WECHAT, "openid-1")
        b, _ = await accounts.login_with_identity(session, WECHAT, "openid-2")
        assert a.id != b.id

    async def test_same_external_id_from_different_providers_does_not_collide(
        self, session, accounts
    ) -> None:
        """匹配键是 `(provider, external_id)` 两列，不是单列。

        不同平台的 id 空间互不相关，撞上同一个字符串完全可能 —— 要是只按
        external_id 匹配，一个 QQ 用户就能登进某个微信用户的账号。
        """
        wechat_user, _ = await accounts.login_with_identity(session, WECHAT, "same-string")
        qq_user, _ = await accounts.login_with_identity(session, QQ, "same-string")
        assert wechat_user.id != qq_user.id

    async def test_disabled_account_cannot_scan_in(self, session, accounts) -> None:
        """停用的账号扫码也进不来 —— 而且这里直说原因。

        密码登录那条路必须把停用混进「用户名或密码不正确」（否则是枚举器），
        但扫码的人已经证明了自己拥有那个微信，含糊其辞只会让他反复重试。
        """
        user, _ = await accounts.login_with_identity(session, WECHAT, "openid-1")
        await accounts.set_active(session, user.username, False)

        with pytest.raises(AccountDisabled):
            await accounts.login_with_identity(session, WECHAT, "openid-1")

    async def test_signup_can_be_refused(self, session, accounts) -> None:
        with pytest.raises(SignupDisabled):
            await accounts.login_with_identity(session, WECHAT, "openid-new", allow_signup=False)
        assert await session.scalar(select(func.count()).select_from(User)) == 0

    async def test_bound_identity_still_logs_in_when_signup_is_off(self, session, accounts) -> None:
        """关掉注册只该挡住新人，不该把老用户一起锁在门外。"""
        await accounts.login_with_identity(session, WECHAT, "openid-1")
        user, created = await accounts.login_with_identity(
            session, WECHAT, "openid-1", allow_signup=False
        )
        assert created is False
        assert user is not None

    async def test_explicit_username_is_honored(self, session, accounts) -> None:
        user, _ = await accounts.login_with_identity(
            session, WECHAT, "openid-1", username="zhangsan"
        )
        assert user.username == "zhangsan"

    async def test_explicit_username_collision_is_not_silently_renamed(
        self, session, accounts
    ) -> None:
        """调用方指定的用户名撞了就报错，不能替他改掉。"""
        await accounts.create_user(session, "taken", "pw", UserRole.GUEST)

        with pytest.raises(UsernameTaken):
            await accounts.login_with_identity(session, WECHAT, "openid-1", username="taken")

    async def test_autogenerated_username_survives_a_collision(
        self, session, accounts, monkeypatch
    ) -> None:
        """自动生成的用户名撞了要换一个重试，不能把注册打挂。

        这里把生成器钉成「第一次返回一个已占用的名字」，模拟那次碰撞。
        """
        from funauth.services import identity as identity_mod

        names = iter(["occupied", "free_name"])
        monkeypatch.setattr(identity_mod, "default_identity_username", lambda provider: next(names))
        await accounts.create_user(session, "occupied", "pw", UserRole.GUEST)

        user, created = await accounts.login_with_identity(session, WECHAT, "openid-1")
        assert created is True
        assert user.username == "free_name"

    async def test_display_name_is_stored_but_never_matched_on(self, session, accounts) -> None:
        """昵称只用来显示。它来自外部、随时能改，不能参与任何判定。"""
        user, _ = await accounts.login_with_identity(
            session, WECHAT, "openid-1", display_name="张三"
        )
        identity = (await accounts.list_identities(session, user.id))[0]
        assert identity.display_name == "张三"

        # 同一个 openid 换个昵称再来，还是同一个账号
        again, created = await accounts.login_with_identity(
            session, WECHAT, "openid-1", display_name="李四"
        )
        assert created is False and again.id == user.id


class TestNoAutoMerge:
    async def test_identities_never_merge_by_display_name_or_target(
        self, session, accounts
    ) -> None:
        """两个外部身份即使看起来是「同一个人」也不自动合并。

        这是本模块唯一的真安全坑：如果微信返回的邮箱能用来认领一个同邮箱的
        已有账号，攻击者只要在微信侧把邮箱改成受害者的，扫一下码就登进了对方
        账号。所以匹配键只有 `(provider, external_id)`。
        """
        pw_user = await accounts.create_user(session, "victim", "pw", UserRole.ADMIN)
        await accounts.link_identity(session, pw_user, AuthProvider.EMAIL, "victim@example.com")

        # 攻击者的微信，昵称和邮箱都伪装成受害者
        attacker, created = await accounts.login_with_identity(
            session, WECHAT, "attacker-openid", display_name="victim@example.com"
        )
        assert created is True
        assert attacker.id != pw_user.id
        assert attacker.role is UserRole.GUEST


class TestLinkUnlink:
    async def test_link_then_login(self, session, accounts) -> None:
        user = await accounts.create_user(session, "boss", "pw", UserRole.ADMIN)
        await accounts.link_identity(session, user, WECHAT, "openid-1")

        same, created = await accounts.login_with_identity(session, WECHAT, "openid-1")
        assert created is False
        assert same.id == user.id
        assert same.role is UserRole.ADMIN, "绑定不该改动角色"

    async def test_link_is_idempotent(self, session, accounts) -> None:
        """用户在两个标签页里各点一次「绑定微信」不该报错。"""
        user = await accounts.create_user(session, "boss", "pw", UserRole.ADMIN)
        first = await accounts.link_identity(session, user, WECHAT, "openid-1")
        second = await accounts.link_identity(session, user, WECHAT, "openid-1")
        assert first.id == second.id
        assert await session.scalar(select(func.count()).select_from(Identity)) == 1

    async def test_link_refuses_to_steal_someone_elses_identity(self, session, accounts) -> None:
        """这个微信已经绑在别人账号上了 —— 不自动改绑。

        自动改绑等于让一次误操作把对方的登录方式搬走，而对方毫不知情。
        """
        owner, _ = await accounts.login_with_identity(session, WECHAT, "openid-1")
        other = await accounts.create_user(session, "other", "pw", UserRole.GUEST)

        with pytest.raises(IdentityTaken):
            await accounts.link_identity(session, other, WECHAT, "openid-1")

        # 原主人照样能登
        still, created = await accounts.login_with_identity(session, WECHAT, "openid-1")
        assert created is False and still.id == owner.id

    async def test_one_account_can_hold_several_providers(self, session, accounts) -> None:
        user = await accounts.create_user(session, "boss", "pw", UserRole.ADMIN)
        await accounts.link_identity(session, user, WECHAT, "openid-1")
        await accounts.link_identity(session, user, QQ, "qq-1")
        await accounts.link_identity(session, user, AuthProvider.EMAIL, "boss@example.com")

        assert len(await accounts.list_identities(session, user.id)) == 3
        # 哪条路进来都是同一个账号
        for provider, external in [(WECHAT, "openid-1"), (QQ, "qq-1")]:
            who, created = await accounts.login_with_identity(session, provider, external)
            assert created is False and who.id == user.id

    async def test_unlink_removes_one_provider(self, session, accounts) -> None:
        user = await accounts.create_user(session, "boss", "pw", UserRole.ADMIN)
        await accounts.link_identity(session, user, WECHAT, "openid-1")
        await accounts.link_identity(session, user, QQ, "qq-1")

        assert await accounts.unlink_identity(session, user, WECHAT) is True
        assert [i.provider for i in await accounts.list_identities(session, user.id)] == [QQ]

    async def test_unlink_what_was_never_bound_is_false_not_an_error(
        self, session, accounts
    ) -> None:
        user = await accounts.create_user(session, "boss", "pw", UserRole.ADMIN)
        assert await accounts.unlink_identity(session, user, WECHAT) is False

    async def test_unlink_refuses_to_lock_the_user_out(self, session, accounts) -> None:
        """最后一种登录方式不许解。

        用户点「解绑微信」的时候不会想到这是他唯一的入口，而解完的后果是一个
        谁都进不去的账号 —— 只能靠运维去库里改。
        """
        user, _ = await accounts.login_with_identity(session, WECHAT, "openid-1")
        assert user.password_hash is None

        with pytest.raises(LastLoginMethod):
            await accounts.unlink_identity(session, user, WECHAT)

        # 还在，还能登
        who, created = await accounts.login_with_identity(session, WECHAT, "openid-1")
        assert created is False and who.id == user.id

    async def test_unlink_is_allowed_once_a_password_exists(self, session, accounts) -> None:
        """设了密码之后就有退路了，这时候可以解绑。"""
        user, _ = await accounts.login_with_identity(session, WECHAT, "openid-1")
        await accounts.set_password(session, user.username, "newpw123")
        await session.refresh(user)

        assert await accounts.unlink_identity(session, user, WECHAT) is True
        assert await accounts.authenticate(session, user.username, "newpw123")

    async def test_count_login_methods_counts_password_too(self, session, accounts) -> None:
        user = await accounts.create_user(session, "boss", "pw", UserRole.ADMIN)
        assert await accounts.count_login_methods(session, user) == 1

        await accounts.link_identity(session, user, WECHAT, "openid-1")
        assert await accounts.count_login_methods(session, user) == 2


class TestUsernameGeneration:
    def test_generated_names_are_prefixed_and_unique(self) -> None:
        names = {default_identity_username(WECHAT) for _ in range(200)}
        assert len(names) == 200, "生成器撞号了"
        assert all(n.startswith("wechat_") for n in names)

    def test_generated_names_do_not_leak_a_sequence(self) -> None:
        """不能是 `wechat_1`、`wechat_2` —— 那把「本站有多少微信用户」和
        「我是第几个」一起写在用户名里了。"""
        suffixes = [default_identity_username(WECHAT).removeprefix("wechat_") for _ in range(20)]
        assert not any(s.isdigit() and int(s) < 1000 for s in suffixes)
