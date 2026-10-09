"""邮箱 / 短信验证码：签发、限频、校验、限次、凭码登录。"""

from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import func, select

from funauth import (
    AuthProvider,
    VerificationFailed,
    VerificationThrottled,
    normalize_target,
)
from funauth.models.types import utcnow
from funauth.services.verification import DEFAULT_MAX_ATTEMPTS

from .conftest import User, VerificationCode

EMAIL = AuthProvider.EMAIL
PHONE = AuthProvider.PHONE
TARGET = "someone@example.com"


class TestIssue:
    async def test_plaintext_is_returned_but_never_stored(self, session, accounts) -> None:
        """明文只在返回值里出现一次，库里只有哈希。

        这是凭据，和密码同等对待 —— 库被读一眼就等于所有在途验证码泄漏，而
        验证码能直接登进账号。
        """
        code, record = await accounts.issue_verification_code(session, EMAIL, TARGET)

        assert code.isdigit() and len(code) == 6
        assert record.code_hash != code
        assert code not in record.code_hash

        stored = await session.scalar(select(VerificationCode.code_hash))
        assert code not in stored

    async def test_code_keeps_leading_zeros(self, session, accounts, monkeypatch) -> None:
        """`"012345"` 不能变成 `12345` —— 用户照着短信输的是 6 位。"""
        from funauth.services import verification as vmod

        monkeypatch.setattr(vmod, "generate_verification_code", lambda length=6: "012345")
        code, _ = await accounts.issue_verification_code(session, EMAIL, TARGET)
        assert code == "012345"

    async def test_resend_is_throttled(self, session, accounts) -> None:
        """连着发第二次要被挡住。

        短信是按条计费的外部调用 —— 不限频的接口既能轰炸别人手机，又能刷光
        你账上余额。
        """
        await accounts.issue_verification_code(session, EMAIL, TARGET)

        with pytest.raises(VerificationThrottled):
            await accounts.issue_verification_code(session, EMAIL, TARGET)

    async def test_throttle_is_per_target(self, session, accounts) -> None:
        """限的是单个标识，不是整个接口 —— 否则一个人能卡住所有人注册。"""
        await accounts.issue_verification_code(session, EMAIL, TARGET)
        code, _ = await accounts.issue_verification_code(session, EMAIL, "other@example.com")
        assert code

    async def test_throttle_window_expires(self, session, accounts) -> None:
        past = utcnow() - timedelta(seconds=120)
        await accounts.issue_verification_code(session, EMAIL, TARGET, now=past)

        code, _ = await accounts.issue_verification_code(session, EMAIL, TARGET)
        assert code

    async def test_reissue_invalidates_the_previous_code(self, session, accounts) -> None:
        """只有最后发出去的那个码有效。

        同时有三个有效码（用户连点了三次「重新发送」）等于把爆破成功率翻三倍，
        而且「我该输哪个」对用户也是困惑。
        """
        old_code, _ = await accounts.issue_verification_code(session, EMAIL, TARGET)
        new_code, _ = await accounts.issue_verification_code(
            session, EMAIL, TARGET, min_interval_seconds=0
        )
        assert old_code != new_code

        with pytest.raises(VerificationFailed):
            await accounts.verify_code(session, EMAIL, TARGET, old_code)

        await accounts.verify_code(session, EMAIL, TARGET, new_code)  # 不抛就算过


class TestVerify:
    async def test_happy_path_consumes_the_code(self, session, accounts) -> None:
        code, _ = await accounts.issue_verification_code(session, EMAIL, TARGET)

        await accounts.verify_code(session, EMAIL, TARGET, code)
        await session.commit()

        # 一次性：同一个码不能再用
        with pytest.raises(VerificationFailed):
            await accounts.verify_code(session, EMAIL, TARGET, code)

    async def test_wrong_code_fails(self, session, accounts) -> None:
        code, _ = await accounts.issue_verification_code(session, EMAIL, TARGET)
        wrong = "000000" if code != "000000" else "111111"

        with pytest.raises(VerificationFailed):
            await accounts.verify_code(session, EMAIL, TARGET, wrong)

    async def test_expired_code_fails(self, session, accounts) -> None:
        code, _ = await accounts.issue_verification_code(session, EMAIL, TARGET, ttl_seconds=60)

        with pytest.raises(VerificationFailed):
            await accounts.verify_code(
                session, EMAIL, TARGET, code, now=utcnow() + timedelta(seconds=61)
            )

    async def test_all_failure_reasons_share_one_message(self, session, accounts) -> None:
        """不存在 / 不对 / 已过期 / 已用过，四种共用一句话。

        分开报就等于告诉爆破方「这个码是对的，只是过期了」—— 把搜索空间白送。
        """
        code, _ = await accounts.issue_verification_code(session, EMAIL, TARGET)
        wrong = "000000" if code != "000000" else "111111"
        await accounts.verify_code(session, EMAIL, TARGET, code)
        await session.commit()

        messages = set()
        cases = [
            (TARGET, code),  # 已用过
            (TARGET, wrong),  # 不对（而且已经没有在途的码了）
            ("nobody@example.com", "123456"),  # 这个标识压根没发过码
        ]
        for target, attempt in cases:
            with pytest.raises(VerificationFailed) as err:
                await accounts.verify_code(session, EMAIL, target, attempt)
            messages.add(str(err.value))
        assert len(messages) == 1, f"失败理由泄漏了区别：{messages}"

    async def test_attempts_are_capped(self, session, accounts) -> None:
        """试错次数有上限，超了直接作废不等过期。

        6 位数字 100 万种组合，不限次的话几分钟就能刷完。
        """
        code, _ = await accounts.issue_verification_code(session, EMAIL, TARGET)
        wrong = "000000" if code != "000000" else "111111"

        for _ in range(DEFAULT_MAX_ATTEMPTS):
            with pytest.raises(VerificationFailed):
                await accounts.verify_code(session, EMAIL, TARGET, wrong)

        # 现在连正确的码也不认了 —— 这张码已经废了
        with pytest.raises(VerificationFailed):
            await accounts.verify_code(session, EMAIL, TARGET, code)

    async def test_the_attempt_counter_survives_a_rollback(self, session, accounts) -> None:
        """这条是整个限次机制的命门。

        失败时调用方（FastAPI 宿主的会话依赖）会 rollback。要是计数跟着回滚，
        这个上限就完全不存在 —— 爆破方每次失败都顺手帮自己把计数清零。所以
        递增是单独提交的，在校验结果出来之前。
        """
        code, _ = await accounts.issue_verification_code(session, EMAIL, TARGET)
        wrong = "000000" if code != "000000" else "111111"

        with pytest.raises(VerificationFailed):
            await accounts.verify_code(session, EMAIL, TARGET, wrong)
        await session.rollback()  # 模拟宿主的异常处理

        assert await session.scalar(select(VerificationCode.attempts)) == 1, (
            "试错计数被回滚掉了，限次形同虚设"
        )

    async def test_consume_does_not_commit(self, session, accounts) -> None:
        """消耗那一步不提交 —— 要和后面的建号同生共死。

        和 `consume_invite` 完全一样：建号失败时码不该白白作废，否则用户得
        重新收一遍验证码，而他什么都没做错。
        """
        code, _ = await accounts.issue_verification_code(session, EMAIL, TARGET)

        await accounts.verify_code(session, EMAIL, TARGET, code)
        await session.rollback()

        assert await session.scalar(select(VerificationCode.consumed_at)) is None
        # 回滚之后这个码还能用
        await accounts.verify_code(session, EMAIL, TARGET, code)


class TestNormalization:
    def test_email_case_and_space_are_folded(self) -> None:
        assert normalize_target(EMAIL, "  Me@Example.COM ") == "me@example.com"

    def test_phone_separators_are_stripped(self) -> None:
        assert normalize_target(PHONE, "+86 138-0013-8000") == "+8613800138000"

    def test_phone_country_code_is_not_guessed(self) -> None:
        """不猜国家码 —— 猜错就是把码发给另一个国家的另一个人。"""
        assert normalize_target(PHONE, "13800138000") == "13800138000"

    async def test_issue_and_verify_agree_on_normalization(self, session, accounts) -> None:
        """大小写不同的同一个邮箱必须是同一个标识。

        不规整的后果不是报错，是悄悄多出一个账号：第一次用 `Me@Example.com`
        注册、第二次输 `me@example.com`，于是他发现自己的数据「不见了」。
        """
        code, _ = await accounts.issue_verification_code(session, EMAIL, "Me@Example.COM")
        await accounts.verify_code(session, EMAIL, "me@example.com", code)

    async def test_case_variants_land_on_one_account(self, session, accounts) -> None:
        first, created_first = await accounts.login_with_code(
            session, EMAIL, "Me@Example.com", await _fresh_code(accounts, session, "Me@Example.com")
        )
        second, created_second = await accounts.login_with_code(
            session, EMAIL, "me@EXAMPLE.com", await _fresh_code(accounts, session, "me@example.com")
        )

        assert created_first is True
        assert created_second is False
        assert first.id == second.id
        assert await session.scalar(select(func.count()).select_from(User)) == 1


async def _fresh_code(accounts, session, target: str) -> str:
    code, _ = await accounts.issue_verification_code(session, EMAIL, target, min_interval_seconds=0)
    return code


class TestLoginWithCode:
    async def test_first_login_creates_an_account(self, session, accounts) -> None:
        code, _ = await accounts.issue_verification_code(session, EMAIL, TARGET)
        user, created = await accounts.login_with_code(session, EMAIL, TARGET, code)

        assert created is True
        assert user.password_hash is None, "验证码注册的账号不该有密码"
        assert user.username.startswith("email_")

    async def test_second_login_reuses_the_account(self, session, accounts) -> None:
        first, _ = await accounts.login_with_code(
            session, EMAIL, TARGET, await _fresh_code(accounts, session, TARGET)
        )
        second, created = await accounts.login_with_code(
            session, EMAIL, TARGET, await _fresh_code(accounts, session, TARGET)
        )
        assert created is False and first.id == second.id

    async def test_wrong_code_creates_nothing(self, session, accounts) -> None:
        await accounts.issue_verification_code(session, EMAIL, TARGET)

        with pytest.raises(VerificationFailed):
            await accounts.login_with_code(session, EMAIL, TARGET, "000000")
        await session.rollback()

        assert await session.scalar(select(func.count()).select_from(User)) == 0

    async def test_email_and_wechat_can_share_one_account(self, session, accounts) -> None:
        """同一个人既能用邮箱登录又能用微信登录 —— 身份表里是两行，账号是一个。

        这是「一张身份表而不是给 User 加列」换来的，不需要任何额外关联逻辑。
        """
        user, _ = await accounts.login_with_code(
            session, EMAIL, TARGET, await _fresh_code(accounts, session, TARGET)
        )
        await accounts.link_identity(session, user, AuthProvider.WECHAT, "openid-1")

        via_wechat, created = await accounts.login_with_identity(
            session, AuthProvider.WECHAT, "openid-1"
        )
        assert created is False and via_wechat.id == user.id
        assert len(await accounts.list_identities(session, user.id)) == 2
