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

    ## 事务边界

    每个方法都收一个 `AsyncSession`，本包不自己建、不自己关 —— 宿主的会话生命
    周期各不相同（FastAPI 一个请求一个、CLI 一条命令一个、后台任务一批一个）。

    **提交**这件事分三档，不要靠猜：

    - 公开写方法 —— `create_user`、`set_password`、`set_active`、`issue_invite`、
      `revoke_invite`、`register_with_invite`：默认 `commit=True` 自己提交，传
      `commit=False` 则只 flush，提交留给调用方；
    - `consume_invite`：**从不**提交，也没有 `commit` 参数；
    - 读方法：不写不提交。

    默认提交是因为绝大多数调用点就是「建个号」「签张码」这种独立操作，让它们
    每次都手写一句 `await session.commit()` 只是噪音。`commit=False` 是给要把
    账号操作和宿主自己的写入凑进一个事务的场合留的出口（建号 + 建默认工作区、
    一次签发一批邀请码），不然调用方只能去动 `_insert` 这种私有方法。

    `consume_invite` 没有这个开关是刻意的：它必须和建账号同生共死，给它一个
    `commit=True` 的选项等于把「一张一次性码被重名用户名白扣一次」那个坑重新
    挖开。要单独扣一个名额，自己在外面提交。

    **回滚始终是调用方的事。** 本包的方法抛异常时不 rollback —— 会话是宿主的，
    它可能还包着宿主自己的写入。FastAPI 宿主的标准写法（会话依赖里 `except:
    await s.rollback(); raise`）正好覆盖这件事。
    """

    def __init__(
        self,
        *,
        user_model: Any,
        invite_model: Any | None = None,
        identity_model: Any | None = None,
        challenge_model: Any | None = None,
    ) -> None:
        """
        Args:
            user_model: 宿主声明的 User 类，必须带 `UserMixin` 的那几列。
            invite_model: 宿主声明的 InviteCode 类，邀请码注册用。
            identity_model: 宿主声明的 Identity 类（`ExternalIdentityMixin`），
                微信 / QQ / 邮箱 / 手机号这些外部身份登录用。
            challenge_model: 宿主声明的 VerificationCode 类
                （`VerificationCodeMixin`），邮箱 / 短信验证码用。

        后三个都可以不传 —— 只用密码登录的宿主不该被迫建三张空表。传 `None`
        时调用对应方法会炸（`AttributeError` 或 `TypeError`），**刻意不做优雅
        降级**：那只会把「忘了配」变成运行时的静默失败，而登录相关的静默失败
        是最糟的一种。
        """
        self.user_model = user_model
        self.invite_model = invite_model
        self.identity_model = identity_model
        self.challenge_model = challenge_model

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
