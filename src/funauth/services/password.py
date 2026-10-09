"""密码登录与建号。

这是本包目前唯一实现了的登录方式。往后加邮箱验证码、短信验证码、QQ / 微信
扫码，各写一个同形状的 mixin 挂到 `Accounts` 上，共用这里的 `User` 表和
`AccountsBase.get_by_username` 等基础查询。
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from funauth.enums import UserRole
from funauth.errors import BadCredentials, PermissionDenied, UsernameTaken
from funauth.security import hash_password, verify_password
from funauth.services.base import AccountsBase

#: 用户名不存在 / 密码不对 / 账号停用，三种都回这一句。见 `authenticate`。
BAD_CREDENTIALS = "用户名或密码不正确"


class PasswordMixin(AccountsBase):
    """密码登录、角色判定、建号改密。"""

    async def authenticate(self, session: AsyncSession, username: str, password: str) -> Any:
        """校验用户名密码，返回对应账号。

        **不区分「用户不存在」和「密码不对」**，连「账号已停用」也归到同一条
        消息里。分开报的话这个接口就是个用户名枚举器：拿字典刷一遍，回「密码
        不对」的那些就是真实存在的账号，接下来只用对这几个爆破密码。

        停用账号也混进去是同一个道理 —— 「这个用户被停用了」同样确认了它存在。
        真正需要知道区别的是运维自己，而运维看得到数据库。

        Raises:
            BadCredentials: 上述任一种情况。
        """
        user = await self.get_by_username(session, username)
        if user is None or not user.is_active:
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
        self, session: AsyncSession, username: str, password: str, role: UserRole
    ) -> Any:
        """服务端直接建号，角色由调用方指定。自助注册请走 `register_with_invite`。

        Raises:
            UsernameTaken: 用户名已被占用。
        """
        user = await self._insert(session, username, password, role)
        await session.commit()
        await session.refresh(user)
        return user

    async def set_password(self, session: AsyncSession, username: str, password: str) -> bool:
        """重置密码。用户不存在返回 `False`。"""
        user = await self.get_by_username(session, username)
        if user is None:
            return False
        user.password_hash = hash_password(password)
        await session.commit()
        return True

    async def set_active(self, session: AsyncSession, username: str, active: bool) -> bool:
        """启用 / 停用账号。用户不存在返回 `False`。"""
        user = await self.get_by_username(session, username)
        if user is None:
            return False
        user.is_active = active
        await session.commit()
        return True

    async def _insert(
        self, session: AsyncSession, username: str, password: str, role: UserRole
    ) -> Any:
        """查重后插入，**不提交**。

        这里的查重**挡不住并发**（两个请求可以都查到「没占用」然后都插），真正
        的保证是宿主表上的唯一约束。先查一遍只是为了在绝大多数情况下回一句人能
        看懂的「用户名已存在」，而不是把 IntegrityError 原样抛给调用方。
        """
        taken = await session.scalar(
            select(self.user_model.id).where(self.user_model.username == username)
        )
        if taken is not None:
            raise UsernameTaken(f"用户名已存在：{username}")
        user = self.user_model(username=username, password_hash=hash_password(password), role=role)
        session.add(user)
        await session.flush()
        return user
