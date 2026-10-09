"""`Accounts` 门面的基座：持有宿主的模型类。"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession


class AccountsBase:
    """把宿主的模型类绑进来，各登录方式的 mixin 共用。

    ## 为什么是一个实例而不是一组模块级函数

    本包不自带表（见 `funauth.models.mixins`），所以每个函数都得知道宿主的
    `User` / `InviteCode` 类是哪个。三种办法：

    1. 每个函数多一个 `user_model` 参数 —— 调用方每次都要传，噪音大且传错了
       编译期发现不了；
    2. 模块级全局变量 + `configure()` —— import 顺序一变就是个 `None`，而且
       同一个进程里没法接两套表（测试、多租户都会撞）；
    3. **实例持有**（本方案）—— 宿主在自己的绑定模块里建一个单例，别处 import
       它。没有全局可变状态，测试里想换表就再建一个实例。

    ## 为什么不自己管 session

    每个方法都收一个 `AsyncSession`。宿主的事务边界各不相同（FastAPI 一个请求
    一个 session、CLI 一条命令一个、后台任务一批一个），本包无权决定。

    涉及多步写入的方法（`register_with_invite`）在内部**不提交**中间状态，让
    整串操作共享调用方的事务 —— 理由见那个方法的 docstring。
    """

    def __init__(self, *, user_model: Any, invite_model: Any | None = None) -> None:
        """
        Args:
            user_model: 宿主声明的 User 类，必须带 `UserMixin` 的那几列。
            invite_model: 宿主声明的 InviteCode 类。不打算用邀请码注册可以不传，
                传 `None` 时调用邀请码相关方法会 `AttributeError` —— 刻意不做
                优雅降级，那只会把「忘了配」变成运行时的静默失败。
        """
        self.user_model = user_model
        self.invite_model = invite_model

    async def get_by_username(self, session: AsyncSession, username: str) -> Any | None:
        """按用户名取账号，没有返回 `None`。"""
        return await session.scalar(
            select(self.user_model).where(self.user_model.username == username)
        )

    async def get_by_id(self, session: AsyncSession, user_id: Any) -> Any | None:
        """按主键取账号，没有返回 `None`。会话校验用。"""
        return await session.get(self.user_model, user_id)

    async def list_users(self, session: AsyncSession) -> list[Any]:
        """列出全部账号，按用户名排序。"""
        return list(
            await session.scalars(select(self.user_model).order_by(self.user_model.username))
        )
