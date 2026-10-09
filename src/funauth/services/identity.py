"""外部身份：绑定、解绑，以及凭外部身份登录。

## 这一层的边界

本模块只回答一件事：**「`(provider, external_id)` 对应哪个本地账号」**，以及
没有对应账号时怎么开一个。

它**不**负责和第三方握手 —— 微信/QQ 的 code 换 token、state 防 CSRF、各家不同
的回调格式、PC 扫码和公众号授权的差异，这些是宿主的活。划在这里是因为握手要
httpx、要 appid/secret、要跟着平台文档变，而本包核心层现在只依赖 sqlalchemy 和
bcrypt；把一堆平台 SDK 拖进来，每个只用密码登录的宿主都得跟着背。

所以宿主那边长这样：

```python
openid = await wechat_client.exchange(code)          # 宿主：握手
user, created = await accounts.login_with_identity(  # 本包：身份 -> 账号
    session, AuthProvider.WECHAT, openid
)
store.login(request, str(user.id))                   # 宿主：会话
```

邮箱/短信验证码是个例外 —— 那条链路整个在本包里（见 `services/verification.py`），
因为「签发、哈希、原子消耗、限次」全是安全核心，不该让每个宿主重写一遍。宿主
在那边只提供一个「把这段文字发出去」的回调。
"""

from __future__ import annotations

import secrets
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from funauth.enums import AuthProvider, UserRole
from funauth.errors import (
    AccountDisabled,
    IdentityTaken,
    LastLoginMethod,
    SignupDisabled,
    UsernameTaken,
)
from funauth.services.password import PasswordMixin

#: 自动生成用户名时的随机后缀字节数。4 字节 = 8 位十六进制 = 约 43 亿种，
#: 配合下面的重试足够了。
_SUFFIX_BYTES = 4

#: 自动生成用户名撞车后重试几次。撞一次的概率已经极低，撞三次意味着出了别的
#: 问题（比如宿主的唯一约束没建上），这时候该把异常抛出去而不是无限转圈。
_USERNAME_TRIES = 3


def default_identity_username(provider: AuthProvider) -> str:
    """给外部身份注册出来的账号起一个本地用户名，形如 `wechat_3f9c1d2a`。

    为什么非要有个用户名：它是本地的唯一标识，登录日志、运维命令、管理后台的
    列表全靠它指人。而微信不给用户名 —— 昵称能重复、能带 emoji、能随时改，
    当不了唯一键，只能进 `display_name` 当展示用。

    用 `secrets` 而不是递增序号：`wechat_1`、`wechat_2` 这种名字会把「本站有多少
    微信用户」和「我是第几个」一起写在用户名里。
    """
    return f"{provider.value}_{secrets.token_hex(_SUFFIX_BYTES)}"


class IdentityMixin(PasswordMixin):
    """外部身份的绑定关系 + 凭身份登录。

    继承 `PasswordMixin` 是因为首次凭身份登录要落一个账号（复用 `_insert`），
    而解绑时要判断「密码算不算一种还留着的登录方式」。
    """

    async def get_user_by_identity(
        self, session: AsyncSession, provider: AuthProvider, external_id: str
    ) -> Any | None:
        """按外部身份取账号，没绑过返回 `None`。

        这是登录路径上最热的一次查询，靠 `(provider, external_id)` 的唯一约束
        （宿主声明）同时提供唯一性和索引。
        """
        model = self.identity_model
        user_id = await session.scalar(
            select(model.user_id).where(
                model.provider == provider, model.external_id == external_id
            )
        )
        if user_id is None:
            return None
        return await self.get_by_id(session, user_id)

    async def list_identities(self, session: AsyncSession, user_id: Any) -> list[Any]:
        """列出某个账号绑了哪些外部身份。给「账号与安全」页面用。"""
        model = self.identity_model
        return list(
            await session.scalars(
                select(model).where(model.user_id == user_id).order_by(model.provider)
            )
        )

    async def count_login_methods(self, session: AsyncSession, user: Any) -> int:
        """这个账号总共有几种能登进来的方式（密码算一种，每个外部身份算一种）。

        `unlink_identity` 用它来拦住「把自己锁在门外」。
        """
        model = self.identity_model
        bound = await session.scalar(
            select(func.count()).select_from(model).where(model.user_id == user.id)
        )
        return int(bound or 0) + (1 if user.password_hash else 0)

    async def link_identity(
        self,
        session: AsyncSession,
        user: Any,
        provider: AuthProvider,
        external_id: str,
        *,
        display_name: str | None = None,
        commit: bool = True,
    ) -> Any:
        """把一个外部身份绑到**已有**账号上（「账号与安全」里点「绑定微信」）。

        重复绑同一个身份到同一个账号是幂等的，直接返回已有那行 —— 用户在两个
        标签页里各点一次不该报错。

        调用方必须**先**完成和第三方的握手，确认 `external_id` 真的属于当前这个
        人。本方法不做、也没法做这个验证：它只看到一个字符串。

        Raises:
            IdentityTaken: 这个身份已经绑在别的账号上了。不自动改绑 —— 那等于
                让一次误操作把对方的登录方式搬走。
        """
        model = self.identity_model
        existing = await session.scalar(
            select(model).where(model.provider == provider, model.external_id == external_id)
        )
        if existing is not None:
            if existing.user_id != user.id:
                raise IdentityTaken(f"该{provider.value}身份已绑定到其他账号")
            return existing

        identity = model(
            provider=provider,
            external_id=external_id,
            user_id=user.id,
            display_name=display_name,
        )
        session.add(identity)
        if commit:
            await session.commit()
            await session.refresh(identity)
        else:
            await session.flush()
        return identity

    async def unlink_identity(
        self,
        session: AsyncSession,
        user: Any,
        provider: AuthProvider,
        external_id: str | None = None,
        *,
        commit: bool = True,
    ) -> bool:
        """解绑。`external_id` 不传就解掉该账号在这个 provider 下的全部身份。

        Returns:
            解掉了至少一行返回 `True`，本来就没绑返回 `False`。

        Raises:
            LastLoginMethod: 解完就没有任何登录方式了。用户点「解绑微信」的时候
                不会想到这一层，而解完的后果是一个谁都进不去的账号 —— 只能靠
                运维去库里改。宁可拦住并让他先设个密码。
        """
        model = self.identity_model
        conditions = [model.user_id == user.id, model.provider == provider]
        if external_id is not None:
            conditions.append(model.external_id == external_id)

        doomed = list(await session.scalars(select(model).where(*conditions)))
        if not doomed:
            return False

        if await self.count_login_methods(session, user) - len(doomed) <= 0:
            raise LastLoginMethod("这是该账号最后一种登录方式，请先设置密码再解绑")

        for identity in doomed:
            await session.delete(identity)
        if commit:
            await session.commit()
        else:
            await session.flush()
        return True

    async def login_with_identity(
        self,
        session: AsyncSession,
        provider: AuthProvider,
        external_id: str,
        *,
        display_name: str | None = None,
        username: str | None = None,
        allow_signup: bool = True,
        commit: bool = True,
    ) -> tuple[Any, bool]:
        """凭外部身份登录，没绑过就当场开一个账号。

        ## 绝不按邮箱/手机号自动合并账号

        第三方返回的邮箱**不能**用来认领一个同邮箱的已有账号。微信那边的邮箱是
        用户自己填的，攻击者把它改成受害者的邮箱，扫一下码就直接登进了对方账号。
        所以这里的匹配键只有 `(provider, external_id)` 一个，匹配不上就是新账号。

        要把两个账号合起来，必须由**已登录**的用户主动走 `link_identity` ——
        那时候他已经证明了自己同时拥有两边。

        ## 并发

        「查不到就建」挡不住并发：两个请求可以都查到「没绑过」然后都去建号。真正
        的保证是宿主在 `(provider, external_id)` 上的唯一约束 —— 第二个会撞上
        它，这里 catch 住再重查一次，于是两边最后拿到同一个账号而不是两个。
        建号那几步包在 SAVEPOINT 里，撞车只回滚这一小段，不会把调用方在同一个
        事务里已经做的事一起冲掉。

        Args:
            display_name: 第三方那边的昵称之类，只存着给界面显示。
            username: 本地用户名。不传就自动生成（`default_identity_username`）。
                显式传了而且撞车，直接抛 `UsernameTaken` 不重试 —— 那是调用方
                指定的值，替他改掉比报错更糟。
            allow_signup: `False` 时只允许已绑过的身份登录。注册开关关着、或者
                只想让这个入口当「绑定过的人的快捷登录」时用。

        Returns:
            `(账号, 是否新建的)`。第二个值给调用方做引导用 —— 新账号往往要跳
            「补个昵称」或者「同意条款」。

        Raises:
            AccountDisabled: 账号被停用。这里直说，不像密码登录那样含糊 ——
                理由见 `AccountDisabled`。
            SignupDisabled: 没绑过，且 `allow_signup=False`。
            UsernameTaken: 调用方显式指定的 `username` 已被占用。
        """
        user = await self.get_user_by_identity(session, provider, external_id)
        if user is not None:
            if not user.is_active:
                raise AccountDisabled("账号已停用，请联系管理员")
            return user, False

        if not allow_signup:
            raise SignupDisabled("注册入口未开放")

        user = await self._signup_with_identity(
            session,
            provider,
            external_id,
            display_name=display_name,
            username=username,
        )
        if user is None:
            # SAVEPOINT 里撞了唯一约束：别人刚好抢先把这个身份绑好了。重查一次
            # 就能拿到他建的那个账号 —— 这是正常的并发结果，不是错误。
            user = await self.get_user_by_identity(session, provider, external_id)
            if user is None:  # pragma: no cover - 唯一约束没建上才会走到这里
                raise IdentityTaken(
                    f"绑定 {provider.value} 身份时发生冲突，但重查不到对应账号："
                    "请检查 (provider, external_id) 上的唯一约束是否已创建"
                )
            if not user.is_active:
                raise AccountDisabled("账号已停用，请联系管理员")
            return user, False

        if commit:
            await session.commit()
            await session.refresh(user)
        return user, True

    async def _signup_with_identity(
        self,
        session: AsyncSession,
        provider: AuthProvider,
        external_id: str,
        *,
        display_name: str | None,
        username: str | None,
    ) -> Any | None:
        """建号 + 绑身份，**不提交**。撞上身份唯一约束时返回 `None`。

        账号的 `password_hash` 是空的 —— 微信注册进来的人没设过密码，而往里塞
        一个随机密码只会让「这个账号能不能用密码登录」变得谁也说不清。
        """
        explicit = username is not None
        last_try = _USERNAME_TRIES - 1
        for attempt in range(_USERNAME_TRIES):
            name = username if explicit else default_identity_username(provider)
            try:
                async with session.begin_nested():
                    user = await self._insert(session, name, None, UserRole.GUEST)
                    session.add(
                        self.identity_model(
                            provider=provider,
                            external_id=external_id,
                            user_id=user.id,
                            display_name=display_name,
                        )
                    )
                    await session.flush()
                return user
            except UsernameTaken:
                # `_insert` 的预查重拦住了：自动生成的名字撞了一个已有账号。
                if explicit or attempt == last_try:
                    raise
            except IntegrityError:
                # 唯一约束在库里拦住了。两种可能，得分清：别人抢先绑了这个身份
                # （调用方应该重查，拿他建的那个账号），还是自动生成的用户名和
                # 一个并发请求重了（换个名字再来）。
                if explicit:
                    raise
                if await self._identity_exists(session, provider, external_id):
                    return None
                if attempt == last_try:
                    raise
        return None

    async def _identity_exists(
        self, session: AsyncSession, provider: AuthProvider, external_id: str
    ) -> bool:
        """这个外部身份现在绑上了没有。只用来给上面那个 `IntegrityError` 分类。"""
        model = self.identity_model
        found = await session.scalar(
            select(model.id).where(model.provider == provider, model.external_id == external_id)
        )
        return found is not None
