"""邀请码：签发、消耗、吊销，以及凭码注册。"""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from funauth.enums import UserRole
from funauth.errors import InviteUnusable
from funauth.models.types import utcnow
from funauth.services.password import PasswordMixin

#: 码值字母表：大写字母 + 数字，去掉 `0O1I` 和小写 `l`。这些码要靠人念、靠
#: 截图转述，`0/O` 和 `1/I/l` 认错的概率太高，与其让人反复试不如直接不用。
ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
CODE_LENGTH = 8

#: 不存在 / 已吊销 / 已过期 / 已用完共用这一句，理由见 `InviteUnusable`。
UNUSABLE = "邀请码无效或已用完"


def generate_code() -> str:
    """生成一个码值。用 `secrets` 而不是 `random` —— 这是凭据，不是随机数。"""
    return "".join(secrets.choice(ALPHABET) for _ in range(CODE_LENGTH))


def describe_invite_status(code: Any, *, now: datetime | None = None) -> str:
    """这张码当前处于什么状态，给管理界面 / CLI 显示用。

    判定条件和 `InviteMixin.consume_invite` 的 WHERE 一一对应。写歪了不会报错
    （它只负责展示），但会出现「列表里写着可用、注册却说无效」这种最难查的
    不一致，所以两处要一起改。
    """
    moment = now or utcnow()
    if not code.is_active:
        return "已吊销"
    if code.expires_at is not None and code.expires_at <= moment:
        return "已过期"
    if code.used_count >= code.max_uses:
        return "已用完"
    return "可用"


class InviteMixin(PasswordMixin):
    """邀请码的生命周期 + 凭码自助注册。

    继承 `PasswordMixin` 是因为注册最终要落一个密码账号（复用 `_insert`）。
    """

    async def issue_invite(
        self,
        session: AsyncSession,
        *,
        max_uses: int = 1,
        expires_in_days: int | None = None,
        note: str | None = None,
        commit: bool = True,
    ) -> Any:
        """签发一张邀请码并落库。

        Args:
            max_uses: 这张码总共能换出几个账号。
            expires_in_days: 多少天后过期；`None` 表示永不过期。
            note: 备注，给签发的人自己记「这张给谁的」。
            commit: 默认提交。传 `False` 只 flush，把提交留给调用方 —— 要一次
                签发一批、或者和宿主自己的写入同生共死时用。

        Returns:
            已落库的邀请码对象，`code` 字段是生成出来的码值。
        """
        expires_at = utcnow() + timedelta(days=expires_in_days) if expires_in_days else None
        code = self.invite_model(
            code=generate_code(),
            max_uses=max_uses,
            expires_at=expires_at,
            note=note,
        )
        session.add(code)
        if commit:
            await session.commit()
            await session.refresh(code)
        else:
            await session.flush()
        return code

    async def consume_invite(
        self, session: AsyncSession, code: str, *, now: datetime | None = None
    ) -> None:
        """占用这张码的一个名额。

        **一条条件 UPDATE 搞定，不许先 SELECT 判断再 UPDATE。** 先查后改在并发
        下会把一张 `max_uses=1` 的码兑出两个账号：两个请求都读到
        `used_count == 0`、都认为还有名额，然后各自 `+1`。这里把「还能不能用」
        整个塞进 WHERE，由数据库保证只有一个人能把它从 0 改到 1，`rowcount`
        就是裁决结果。

        **不自己提交，也没有 `commit` 参数** —— 调用方（`register_with_invite`）
        要让「扣名额」和「建账号」同生共死：建号那步因为用户名撞车失败时，名额
        必须跟着回滚，否则一张码会因为别人手滑输了个重名用户名而白白少一个名额。
        给它一个 `commit=True` 的选项就是把这个坑重新挖开。

        Raises:
            InviteUnusable: 码不存在、已吊销、已过期，或名额已用完。
        """
        moment = now or utcnow()
        model = self.invite_model
        result = await session.execute(
            update(model)
            .where(
                model.code == code,
                model.is_active.is_(True),
                model.used_count < model.max_uses,
                (model.expires_at.is_(None)) | (model.expires_at > moment),
            )
            .values(used_count=model.used_count + 1)
            .execution_options(synchronize_session=False)
        )
        if not result.rowcount:
            raise InviteUnusable(UNUSABLE)

    async def revoke_invite(self, session: AsyncSession, code: str, *, commit: bool = True) -> bool:
        """吊销一张码。重复吊销是幂等的。

        Args:
            commit: 默认提交，传 `False` 把提交留给调用方。

        Returns:
            码存在返回 `True`，不存在返回 `False`。
        """
        result = await session.execute(
            update(self.invite_model)
            .where(self.invite_model.code == code)
            .values(is_active=False)
            .execution_options(synchronize_session=False)
        )
        if commit:
            await session.commit()
        return bool(result.rowcount)

    async def list_invites(self, session: AsyncSession) -> list[Any]:
        """列出全部邀请码，新的在前。"""
        return list(
            await session.scalars(
                select(self.invite_model).order_by(self.invite_model.created_at.desc())
            )
        )

    @staticmethod
    def describe_invite_status(code: Any, *, now: datetime | None = None) -> str:
        """见模块级的同名函数。"""
        return describe_invite_status(code, now=now)

    async def register_with_invite(
        self,
        session: AsyncSession,
        username: str,
        password: str,
        invite_code: str,
        *,
        commit: bool = True,
    ) -> Any:
        """凭邀请码自助注册一个账号。

        **角色硬编码成 `GUEST`，不接受调用方指定。** 这是这个方法存在的意义：
        注册这条路径通常对公网开放，一旦让它能产出 `ADMIN`，邀请码外泄就等于
        交出后台；而现在最坏结果只是多几个普通用户。要建管理员走 `create_user`。

        扣名额和建账号在**同一个事务**里：用户名撞车时 `consume_invite` 已经
        递增的 `used_count` 跟着回滚 —— 不然别人手滑输了个重名用户名，这张码
        就白少一次，而签发的人完全看不出为什么。

        Args:
            commit: 默认提交。传 `False` 只 flush，提交留给调用方。这两步
                **始终**在一个事务里，`commit=False` 只是把这个事务的边界再往
                外推一层，不会把它们拆开。

        Raises:
            InviteUnusable: 码不存在 / 已吊销 / 已过期 / 已用完。
            UsernameTaken: 用户名已被占用。
        """
        await self.consume_invite(session, invite_code)
        user = await self._insert(session, username, password, UserRole.GUEST)
        if commit:
            await session.commit()
            await session.refresh(user)
        return user
