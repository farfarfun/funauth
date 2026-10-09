from __future__ import annotations

from collections.abc import AsyncIterator

import pytest_asyncio
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.pool import StaticPool

from funauth import (
    Accounts,
    ExternalIdentityMixin,
    InviteCodeMixin,
    TimestampMixin,
    UserMixin,
    VerificationCodeMixin,
)


class Base(DeclarativeBase):
    """测试用的宿主 Base —— 本包不自带，这里演示宿主该怎么接。"""


class User(UserMixin, TimestampMixin, Base):
    __tablename__ = "user"
    __table_args__ = (sa.UniqueConstraint("username", name="uq_user_username"),)


class InviteCode(InviteCodeMixin, TimestampMixin, Base):
    __tablename__ = "invite_code"
    __table_args__ = (sa.UniqueConstraint("code", name="uq_invite_code_code"),)


class PlainInviteCode(InviteCodeMixin, Base):
    """刻意**不挂** `TimestampMixin`。

    时间列是宿主自己的事（宿主可能已经有一套、叫别的名字、或者压根不要），所以
    本包的逻辑不许依赖 `created_at` / `updated_at` 存在。这张表就是那个约束的
    执行版 —— 哪天有人又在 UPDATE 里手写 `updated_at`，用到它的测试会炸。
    """

    __tablename__ = "plain_invite_code"
    __table_args__ = (sa.UniqueConstraint("code", name="uq_plain_invite_code_code"),)


class Identity(ExternalIdentityMixin, TimestampMixin, Base):
    __tablename__ = "identity"
    __table_args__ = (
        # 这条约束不是装饰：它是「两个请求同时拿同一个 openid 进来」唯一的
        # 真实保障。`login_with_identity` 的「查不到就建」靠撞它之后重查。
        sa.UniqueConstraint("provider", "external_id", name="uq_identity_provider_external"),
        sa.ForeignKeyConstraint(
            ["user_id"], ["user.id"], name="fk_identity_user", ondelete="CASCADE"
        ),
    )


class VerificationCode(VerificationCodeMixin, TimestampMixin, Base):
    __tablename__ = "verification_code"


@pytest_asyncio.fixture
async def engine() -> AsyncIterator:
    """每个测试一个独立的内存库。

    StaticPool 让所有连接复用同一个内存数据库 —— 否则 `:memory:` 每开一条连接
    就是一个全新的空库，建表和查询会落在不同的库上。
    """
    eng = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield eng
    await eng.dispose()


@pytest_asyncio.fixture
async def session(engine) -> AsyncIterator[AsyncSession]:
    maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with maker() as s:
        yield s


@pytest_asyncio.fixture
async def accounts() -> Accounts:
    return Accounts(
        user_model=User,
        invite_model=InviteCode,
        identity_model=Identity,
        challenge_model=VerificationCode,
    )
