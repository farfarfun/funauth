"""密码登录与建号。

这是本包目前唯一实现了的登录方式。往后加邮箱验证码、短信验证码、QQ / 微信
扫码，各写一个同形状的 mixin 挂到 `Accounts` 上，共用这里的 `User` 表和
`AccountsBase.get_by_username` 等基础查询。
"""

from __future__ import annotations

import secrets
from functools import cache
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from funauth.enums import UserRole
from funauth.errors import BadCredentials, PermissionDenied, UsernameTaken
from funauth.security import hash_password, verify_password
from funauth.services.base import AccountsBase

#: 用户名不存在 / 密码不对 / 账号停用，三种都回这一句。见 `authenticate`。
BAD_CREDENTIALS = "用户名或密码不正确"


@cache
def _dummy_hash() -> str:
    """一个不对应任何密码的 bcrypt 哈希，用来给「用户不存在」那条路径补上等量计算。

    惰性生成而不是模块级常量：`gensalt()` 要几百毫秒，不该让只是
    `import funauth` 的 CLI 或后台任务白付这笔钱。

    也不写死一个字面量哈希：那样 bcrypt 以后调高默认 cost 时，它的耗时就和真实
    哈希对不上，侧信道又回来了。这里用 `hash_password` 生成，cost 永远跟当前
    默认值一致。
    """
    return hash_password(secrets.token_urlsafe(32))


class PasswordMixin(AccountsBase):
    """密码登录、角色判定、建号改密。"""

    async def authenticate(self, session: AsyncSession, username: str, password: str) -> Any:
        """校验用户名密码，返回对应账号。

        **不区分「用户不存在」和「密码不对」**，连「账号已停用」和「这个账号
        没设密码」也归到同一条消息里。分开报的话这个接口就是个用户名枚举器：
        拿字典刷一遍，回「密码不对」的那些就是真实存在的账号，接下来只用对这
        几个爆破密码。

        停用账号也混进去是同一个道理 —— 「这个用户被停用了」同样确认了它存在。
        「这个账号是微信注册的、没有密码」更是如此，它连对方用什么方式登录都
        一起说了。真正需要知道区别的是运维自己，而运维看得到数据库。

        Raises:
            BadCredentials: 上述任一种情况。
        """
        user = await self.get_by_username(session, username)
        if user is None or not user.is_active or not user.password_hash:
            # 对一个假哈希跑一次 bcrypt 再抛，让这条路径和「密码不对」耗时相当。
            # 不补的话消息虽然一样，响应时间差一个数量级（bcrypt 上百毫秒 vs
            # 一次索引查询不到一毫秒），按耗时排序就能把真实账号筛出来 ——
            # 共用消息的努力全白费。
            verify_password(password, _dummy_hash())
            raise BadCredentials(BAD_CREDENTIALS)
        if not verify_password(password, user.password_hash):
            raise BadCredentials(BAD_CREDENTIALS)
        return user

    @staticmethod
    def require_role(user: Any, role: UserRole) -> None:
        """要求 `user` 正好是 `role` 这个角色，不然抛异常。

        用精确相等而不是「大于等于」：`UserRole` 只有两级，而枚举的定义顺序
        不该悄悄决定权限高低（理由见 `UserRole` 的 docstring）。以后真有三级，
        这里要显式写出每级能干什么，而不是靠排序蒙对。

        Raises:
            PermissionDenied: 角色不匹配。
        """
        if user.role != role:
            raise PermissionDenied("需要管理员权限")

    async def create_user(
        self,
        session: AsyncSession,
        username: str,
        password: str | None,
        role: UserRole,
        *,
        commit: bool = True,
    ) -> Any:
        """服务端直接建号，角色由调用方指定。自助注册请走 `register_with_invite`。

        Args:
            password: `None` 表示不开密码登录 —— 建一个只能用外部身份（微信、
                邮箱验证码）登录的账号时传 `None`，之后用 `set_password` 随时
                可以补上。
            commit: 默认提交。传 `False` 只 flush，把提交留给调用方 —— 要把建号
                和宿主自己的写入（建默认工作区之类）放进同一个事务时用。见
                `AccountsBase` 的「事务边界」一节。

        Raises:
            UsernameTaken: 用户名已被占用。
        """
        user = await self._insert(session, username, password, role)
        if commit:
            await session.commit()
            await session.refresh(user)
        return user

    async def set_password(
        self, session: AsyncSession, username: str, password: str, *, commit: bool = True
    ) -> bool:
        """重置密码。用户不存在返回 `False`。

        Args:
            commit: 默认提交，传 `False` 只 flush。
        """
        user = await self.get_by_username(session, username)
        if user is None:
            return False
        user.password_hash = hash_password(password)
        if commit:
            await session.commit()
        else:
            await session.flush()
        return True

    async def set_active(
        self, session: AsyncSession, username: str, active: bool, *, commit: bool = True
    ) -> bool:
        """启用 / 停用账号。用户不存在返回 `False`。

        Args:
            commit: 默认提交，传 `False` 只 flush。
        """
        user = await self.get_by_username(session, username)
        if user is None:
            return False
        user.is_active = active
        if commit:
            await session.commit()
        else:
            await session.flush()
        return True

    async def _insert(
        self, session: AsyncSession, username: str, password: str | None, role: UserRole
    ) -> Any:
        """查重后插入，**不提交**。

        这里的查重**挡不住并发**（两个请求可以都查到「没占用」然后都插），真正
        的保证是宿主表上的唯一约束。先查一遍只是为了在绝大多数情况下回一句人能
        看懂的「用户名已存在」，而不是把 IntegrityError 原样抛给调用方。

        Args:
            password: `None` 表示这个账号不开密码登录（外部身份注册出来的账号
                走这条路）。注意 `None` 和空串都落成空的 `password_hash`，而
                `authenticate` 对空哈希一律判失败 —— 不会变成「空密码能登进去」。
        """
        taken = await session.scalar(
            select(self.user_model.id).where(self.user_model.username == username)
        )
        if taken is not None:
            raise UsernameTaken(f"用户名已存在：{username}")
        user = self.user_model(
            username=username,
            password_hash=hash_password(password) if password else None,
            role=role,
        )
        session.add(user)
        await session.flush()
        return user
