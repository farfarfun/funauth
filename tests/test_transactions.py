"""事务边界：谁提交、什么时候提交。

`AccountsBase` 的 docstring 对外承诺了一张表（公开写方法默认提交、`commit=False`
只 flush、`consume_invite` 从不提交）。这个文件就是那张表的可执行版本 —— 文档和
实现在这件事上曾经是矛盾的（文档说「什么时候提交由调用方决定」，实现里 6 个写
方法自己 commit），钉住它才不会再分叉。

判定手法统一是「做完之后 rollback，再看还在不在」：提交过的回滚不掉，只 flush
的会消失。
"""

from __future__ import annotations

import inspect

import pytest
from sqlalchemy import select

from funauth import Accounts, UsernameTaken, UserRole

from .conftest import InviteCode, PlainInviteCode, User


class TestDefaultCommits:
    """默认 `commit=True`：调用完就落库了，之后的 rollback 回滚不掉。"""

    async def test_create_user(self, session, accounts) -> None:
        await accounts.create_user(session, "u", "pw", UserRole.GUEST)
        await session.rollback()
        assert await accounts.get_by_username(session, "u") is not None

    async def test_issue_invite(self, session, accounts) -> None:
        # 码值先取出来：`rollback()` 会 expire 这个对象，之后再读属性会触发一次
        # 懒加载，而在异步会话里那是个 MissingGreenlet 而不是我们想验的东西。
        issued = (await accounts.issue_invite(session)).code
        await session.rollback()
        assert await session.scalar(select(InviteCode).where(InviteCode.code == issued))

    async def test_register_with_invite(self, session, accounts) -> None:
        code = await accounts.issue_invite(session)
        await accounts.register_with_invite(session, "newbie", "pw", code.code)
        await session.rollback()
        assert await accounts.get_by_username(session, "newbie") is not None
        assert await session.scalar(select(InviteCode.used_count)) == 1


class TestCommitFalse:
    """`commit=False`：只 flush，提交留给调用方 —— 所以 rollback 能撤掉。

    这是宿主把账号操作和自己的写入凑进一个事务的出口（建号 + 建默认工作区、
    一次签发一批码）。没有它，调用方只能去动 `_insert` 这种私有方法。
    """

    async def test_create_user(self, session, accounts) -> None:
        user = await accounts.create_user(session, "u", "pw", UserRole.GUEST, commit=False)
        # flush 过了，所以主键已经有值 —— 宿主接下来就能拿它建关联行
        assert user.id is not None

        await session.rollback()
        assert await accounts.get_by_username(session, "u") is None

    async def test_create_user_still_detects_duplicates_before_commit(
        self, session, accounts
    ) -> None:
        """同一个未提交的事务里连着建两个同名账号，第二个就该被挡住。"""
        await accounts.create_user(session, "u", "pw", UserRole.GUEST, commit=False)
        with pytest.raises(UsernameTaken):
            await accounts.create_user(session, "u", "pw", UserRole.GUEST, commit=False)

    async def test_issue_invite(self, session, accounts) -> None:
        code = await accounts.issue_invite(session, commit=False)
        assert code.id is not None

        await session.rollback()
        assert await session.scalar(select(InviteCode)) is None

    async def test_set_password(self, session, accounts) -> None:
        await accounts.create_user(session, "u", "old", UserRole.GUEST)

        assert await accounts.set_password(session, "u", "new", commit=False) is True
        await session.rollback()
        assert await accounts.authenticate(session, "u", "old")

    async def test_set_active(self, session, accounts) -> None:
        await accounts.create_user(session, "u", "pw", UserRole.GUEST)

        assert await accounts.set_active(session, "u", False, commit=False) is True
        await session.rollback()
        user = await accounts.get_by_username(session, "u")
        assert user.is_active is True

    async def test_revoke_invite(self, session, accounts) -> None:
        code = await accounts.issue_invite(session)

        assert await accounts.revoke_invite(session, code.code, commit=False) is True
        await session.rollback()
        await session.refresh(code)
        assert code.is_active is True

    async def test_register_with_invite(self, session, accounts) -> None:
        """注册的两步始终同生共死 —— `commit=False` 只是把事务边界往外推。"""
        code = await accounts.issue_invite(session)

        await accounts.register_with_invite(session, "newbie", "pw", code.code, commit=False)
        await session.rollback()

        assert await accounts.get_by_username(session, "newbie") is None
        assert await session.scalar(select(InviteCode.used_count)) == 0


class TestConsumeNeverCommits:
    async def test_consume_invite_has_no_commit_switch(self, accounts) -> None:
        """`consume_invite` 刻意没有 `commit` 参数。

        它必须和建账号同生共死。给它一个 `commit=True` 的选项，就等于把「一张
        一次性码被重名用户名白扣一次」那个坑重新挖开 —— 而那种 bug 签发的人
        完全看不出原因。
        """
        params = inspect.signature(accounts.consume_invite).parameters
        assert "commit" not in params, "consume_invite 不该有 commit 开关"

    async def test_consume_leaves_the_commit_to_the_caller(self, session, accounts) -> None:
        code = await accounts.issue_invite(session, max_uses=2)

        await accounts.consume_invite(session, code.code)
        await session.rollback()

        assert await session.scalar(select(InviteCode.used_count)) == 0


class TestNoTimestampDependency:
    """本包的逻辑不许依赖宿主的表有时间列。

    `consume_invite` / `revoke_invite` 曾经在 `.values()` 里手写 `updated_at`，
    那就隐式要求邀请码表必须有一个**正好叫**这个名字的列 —— 宿主只继承
    `InviteCodeMixin`、或者自己那套时间列叫 `modified_at`，就会在运行时炸。
    现在交给列自己的 `onupdate`，没有这个列也照常跑。
    """

    @pytest.fixture
    def plain_accounts(self) -> Accounts:
        return Accounts(user_model=User, invite_model=PlainInviteCode)

    async def test_full_invite_lifecycle_without_timestamp_columns(
        self, session, plain_accounts
    ) -> None:
        assert not hasattr(PlainInviteCode, "updated_at")

        code = await plain_accounts.issue_invite(session, max_uses=2)
        await plain_accounts.consume_invite(session, code.code)
        await session.commit()
        assert await session.scalar(select(PlainInviteCode.used_count)) == 1

        assert await plain_accounts.revoke_invite(session, code.code) is True
        await session.refresh(code)
        assert code.is_active is False

    async def test_register_works_without_timestamp_columns(self, session, plain_accounts) -> None:
        code = await plain_accounts.issue_invite(session)
        user = await plain_accounts.register_with_invite(session, "newbie", "pw", code.code)
        assert user.role is UserRole.GUEST

    async def test_updated_at_still_advances_when_the_column_exists(
        self, session, accounts
    ) -> None:
        """挂了 `TimestampMixin` 的表，`updated_at` 该照常推进。

        不手写 `.values(updated_at=...)` 不等于放弃这个列 —— `onupdate=utcnow`
        对 Core UPDATE 一样生效。这条测试盯住那个前提。
        """
        code = await accounts.issue_invite(session, max_uses=2)
        before = code.updated_at

        await accounts.consume_invite(session, code.code)
        await session.commit()
        await session.refresh(code)

        assert code.updated_at > before
