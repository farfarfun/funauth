from __future__ import annotations

from collections.abc import AsyncIterator

import pytest_asyncio
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.pool import StaticPool

from funauth import Accounts, InviteCodeMixin, TimestampMixin, UserMixin


class Base(DeclarativeBase):
    """测试用的宿主 Base —— 本包不自带，这里演示宿主该怎么接。"""


class User(UserMixin, TimestampMixin, Base):
    __tablename__ = "user"
    __table_args__ = (sa.UniqueConstraint("username", name="uq_user_username"),)


class InviteCode(InviteCodeMixin, TimestampMixin, Base):
    __tablename__ = "invite_code"
    __table_args__ = (sa.UniqueConstraint("code", name="uq_invite_code_code"),)


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
    return Accounts(user_model=User, invite_model=InviteCode)
