"""邮箱 / 短信验证码：签发、校验，以及凭验证码登录。

## 为什么这条链路整个在本包里

和微信扫码相反 —— 那边只把「身份 -> 账号」留在本包，握手交给宿主（见
`services/identity.py`）。验证码这边**全在本包**：签发、哈希、原子消耗、试错
限次、发送限频，每一条都是安全核心，让每个宿主自己写一遍必然有人写漏。

宿主只提供一件事：把这段文字发出去。发送通道是宿主的（SES / 阿里云 / 腾讯云，
各家 SDK 完全不同），但凭据逻辑不是。

```python
code, _ = await accounts.issue_verification_code(session, AuthProvider.EMAIL, email)
await my_mailer.send(email, f"验证码：{code}，10 分钟内有效")   # 宿主
# ... 用户把码填回来
user, created = await accounts.login_with_code(session, AuthProvider.EMAIL, email, code)
```

## 形状照抄邀请码

限期 + 一次性 + 原子消耗，消耗同样只许写成一条带守卫的 UPDATE（理由见
`InviteMixin.consume_invite`）。两处的区别只有两个：这里存哈希不存明文，以及
这里有试错计数 —— 6 位数字只有 100 万种组合。
"""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from funauth.enums import AuthProvider
from funauth.errors import VerificationFailed, VerificationThrottled
from funauth.models.types import utcnow
from funauth.security import hash_password, verify_password
from funauth.services.identity import IdentityMixin
from funauth.services.password import _dummy_hash

#: 验证码字母表。纯数字 —— 这东西要在手机上念着输、从短信里拷，掺字母只是
#: 给用户添麻烦，而长度换来的熵比字符集换来的直观得多。
DIGITS = "0123456789"
CODE_LENGTH = 6

#: 默认有效期 10 分钟。短了用户收不及（邮件延迟几十秒很常见），长了给爆破
#: 更多窗口。
DEFAULT_TTL_SECONDS = 600

#: 同一个标识两次发送之间至少隔这么久。防的不只是骚扰 —— 短信是按条计费的
#: 外部调用，不限频的接口既能轰炸别人手机又能刷光你账上余额。
DEFAULT_MIN_INTERVAL_SECONDS = 60

#: 一个码最多能试错几次，超了直接作废不等过期。6 位数字 100 万种组合，
#: 5 次的成功率是 1/200000；不限次的话几分钟就能刷完。
DEFAULT_MAX_ATTEMPTS = 5

#: 不存在 / 不对 / 已过期 / 已用过 / 试错超限，五种共用这一句。
#: 理由见 `VerificationFailed`。
FAILED = "验证码无效或已过期"


def generate_verification_code(length: int = CODE_LENGTH) -> str:
    """生成一个验证码。用 `secrets` 而不是 `random` —— 这是凭据。

    返回字符串而不是整数：`"012345"` 和 `12345` 不是一回事，前导零必须留着。
    """
    return "".join(secrets.choice(DIGITS) for _ in range(length))


def normalize_target(provider: AuthProvider, target: str) -> str:
    """把标识规整成一个稳定的形式，**签发和校验必须用同一个结果**。

    不规整的后果不是报错，是悄悄多出一个账号：用户第一次用 `Me@Example.com`
    注册、第二次输 `me@example.com`，在身份表里就是两条不同的 `external_id`，
    于是他发现自己的数据「不见了」。

    - 邮箱：去空白 + 转小写。严格按 RFC，local part 是区分大小写的，但现实中
      没有任何邮件服务商真的区分，而不转小写换来的是上面那个问题。
    - 手机号：只去掉空格、横线和括号。**不猜国家码** —— 猜错了就是把码发给
      另一个国家的另一个人。宿主应该传 E.164（`+8613800138000`）。
    """
    cleaned = target.strip()
    if provider is AuthProvider.EMAIL:
        return cleaned.lower()
    if provider is AuthProvider.PHONE:
        return cleaned.replace(" ", "").replace("-", "").replace("(", "").replace(")", "")
    return cleaned


class VerificationMixin(IdentityMixin):
    """验证码的签发与校验 + 凭验证码登录。

    继承 `IdentityMixin` 是因为校验通过之后要走同一条「身份 -> 账号」的路：
    验证过的邮箱就是一个 `external_id`，和微信的 openid 在身份表里没有区别。
    """

    async def issue_verification_code(
        self,
        session: AsyncSession,
        provider: AuthProvider,
        target: str,
        *,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        min_interval_seconds: int = DEFAULT_MIN_INTERVAL_SECONDS,
        length: int = CODE_LENGTH,
        now: datetime | None = None,
        commit: bool = True,
    ) -> tuple[str, Any]:
        """签发一个验证码，并作废这个标识之前所有还没用的码。

        作废旧码是刻意的：同时有三个有效码（用户连点了三次「重新发送」）等于把
        爆破的成功率翻三倍，而且「我该输哪个」对用户也是困惑。永远只有最后发出
        去的那个有效。

        Returns:
            `(明文验证码, 已落库的记录)`。**明文只在这里出现这一次** —— 库里存
            的是 bcrypt 哈希，拿不回来。调用方必须当场把它发出去，不要记日志、
            不要塞进响应体回给前端（那等于公开所有人的验证码）。

        Raises:
            VerificationThrottled: 距上次发送还不到 `min_interval_seconds`。
        """
        moment = now or utcnow()
        key = normalize_target(provider, target)
        model = self.challenge_model

        last_issued = await session.scalar(
            select(func.max(model.issued_at)).where(model.provider == provider, model.target == key)
        )
        if last_issued is not None:
            waited = (moment - last_issued).total_seconds()
            if waited < min_interval_seconds:
                raise VerificationThrottled(
                    f"发送过于频繁，请 {int(min_interval_seconds - waited) + 1} 秒后再试"
                )

        await session.execute(
            update(model)
            .where(
                model.provider == provider,
                model.target == key,
                model.consumed_at.is_(None),
            )
            .values(consumed_at=moment)
            .execution_options(synchronize_session=False)
        )

        code = generate_verification_code(length)
        record = model(
            provider=provider,
            target=key,
            code_hash=hash_password(code),
            issued_at=moment,
            expires_at=moment + timedelta(seconds=ttl_seconds),
        )
        session.add(record)
        if commit:
            await session.commit()
            await session.refresh(record)
        else:
            await session.flush()
        return code, record

    async def verify_code(
        self,
        session: AsyncSession,
        provider: AuthProvider,
        target: str,
        code: str,
        *,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        now: datetime | None = None,
    ) -> None:
        """校验一个验证码并当场消耗掉它。通过就正常返回，不通过抛异常。

        ## 先记账，再判断

        试错次数的递增是**单独提交**的，在校验结果出来之前。这是故意的：失败时
        调用方（或 FastAPI 宿主的会话依赖）会 rollback，而次数要是跟着回滚，
        这个上限就完全不存在了 —— 爆破方可以无限次试，每次失败都顺手帮他把
        计数清零。安全计数器必须活过它所记录的那次失败。

        代价是这个方法在失败路径上会提交一次。所以**请在请求的早期调用它**，
        别在同一个会话里攒了一堆待写的东西之后才调 —— 那些会跟着一起提交。

        ## 消耗这一步不提交

        和 `consume_invite` 完全一样：消耗要和后面的建号同生共死，否则建号失败
        时码已经作废，用户得重新收一遍。提交留给 `login_with_code` 或调用方。

        Raises:
            VerificationFailed: 码不存在 / 不对 / 已过期 / 已用过 / 试错超限。
                五种共用一条消息 —— 分开报就等于告诉爆破方「这个码是对的，只是
                过期了」，把搜索空间白送给他。
        """
        moment = now or utcnow()
        key = normalize_target(provider, target)
        model = self.challenge_model

        record = await session.scalar(
            select(model)
            .where(
                model.provider == provider,
                model.target == key,
                model.consumed_at.is_(None),
                model.expires_at > moment,
            )
            .order_by(model.issued_at.desc())
            .limit(1)
        )
        if record is None:
            # 压根没有在途的码。也跑一次 bcrypt 再抛 —— 和 `authenticate` 同一个
            # 道理：不补的话「这个邮箱有没有在等验证码」能从响应时间上读出来。
            verify_password(code, _dummy_hash())
            raise VerificationFailed(FAILED)

        # 下面要 commit，而 commit 会 expire 这个对象。先把要用的值取出来，
        # 否则之后读 `record.code_hash` 会触发一次懒加载 —— 在异步会话里那是
        # 个 MissingGreenlet。
        record_id = record.id
        code_hash = record.code_hash

        counted = await session.execute(
            update(model)
            .where(
                model.id == record_id,
                model.consumed_at.is_(None),
                model.attempts < max_attempts,
            )
            .values(attempts=model.attempts + 1)
            .execution_options(synchronize_session=False)
        )
        await session.commit()
        if not counted.rowcount:
            # 守卫在 WHERE 里：试错已超限，或者这个码刚被并发请求用掉了。
            verify_password(code, _dummy_hash())
            raise VerificationFailed(FAILED)

        if not verify_password(code, code_hash):
            raise VerificationFailed(FAILED)

        consumed = await session.execute(
            update(model)
            .where(model.id == record_id, model.consumed_at.is_(None))
            .values(consumed_at=moment)
            .execution_options(synchronize_session=False)
        )
        if not consumed.rowcount:
            # 码是对的，但有人在这两步之间抢先用掉了它。一次性就是一次性。
            raise VerificationFailed(FAILED)

    async def login_with_code(
        self,
        session: AsyncSession,
        provider: AuthProvider,
        target: str,
        code: str,
        *,
        display_name: str | None = None,
        username: str | None = None,
        allow_signup: bool = True,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        now: datetime | None = None,
        commit: bool = True,
    ) -> tuple[Any, bool]:
        """校验验证码，然后凭这个标识登录（没绑过就当场开账号）。

        验证通过的邮箱 / 手机号就当成一个 `external_id` 存进身份表 —— 和微信的
        openid 在那张表里是同一个形状，所以「同一个人既能用邮箱登录又能用微信
        登录」天然成立，不需要额外的关联逻辑。

        消耗验证码和建账号在**同一个事务**里（`verify_code` 的消耗那步不提交），
        所以建号失败时码不会白白作废。

        Returns:
            `(账号, 是否新建的)`。

        Raises:
            VerificationFailed: 验证码那一关没过。
            AccountDisabled: 账号被停用。
            SignupDisabled: 这个标识没绑过账号，且 `allow_signup=False`。
        """
        await self.verify_code(session, provider, target, code, max_attempts=max_attempts, now=now)
        return await self.login_with_identity(
            session,
            provider,
            normalize_target(provider, target),
            display_name=display_name,
            username=username,
            allow_signup=allow_signup,
            commit=commit,
        )
