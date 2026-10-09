"""可移植的列类型与主键生成。

宿主项目往往已经有自己的一套（funflix 就有），那就用宿主的 —— 这里提供的是
给**还没有**的项目用的默认实现。两边 DDL 刻意保持一致（`PkType` 都是
`sa.Uuid`、时间列都是 `DateTime(timezone=True)`），所以换过来不需要写迁移。
"""

from __future__ import annotations

import os
import time
import uuid
from datetime import UTC, datetime
from typing import Any

import sqlalchemy as sa

#: 主键。PostgreSQL 上是原生 uuid 列，SQLite 上退化成 CHAR(32) 存十六进制。
#: 客户端生成（见 `uuid7`），不依赖数据库分配。
PkType = sa.Uuid(as_uuid=True)


def utcnow() -> datetime:
    """当前 UTC 时间（tz-aware）。"""
    return datetime.now(UTC)


def uuid7() -> uuid.UUID:
    """时间排序主键（RFC 9562 UUIDv7）：48 位毫秒时间戳 + 74 位随机数。

    字典序等于生成顺序，所以 `ORDER BY id DESC` 就是「最新优先」，不用再加一列
    时间索引；同时全局唯一，多机并发生成不会撞号。

    标准库要到 3.14 才有 `uuid.uuid7()`，本包下限是 3.12，这里自己实现。
    """
    ts_ms = time.time_ns() // 1_000_000
    rand = int.from_bytes(os.urandom(10), "big")
    rand_a = (rand >> 62) & 0xFFF
    rand_b = rand & 0x3FFFFFFFFFFFFFFF
    value = ((ts_ms & 0xFFFFFFFFFFFF) << 80) | (0x7 << 76) | (rand_a << 64) | (0b10 << 62) | rand_b
    return uuid.UUID(int=value)


class UTCDateTime(sa.types.TypeDecorator):
    """始终以 UTC-aware datetime 进出的 DateTime。

    SQLite 没有原生时间类型，`DateTime(timezone=True)` 读回来是 naive 的，而
    PostgreSQL 读回来是 aware 的 —— 不处理的话同一份代码在两个库上行为不一致。
    这里在绑定期强制转 UTC、在返回期补齐 tzinfo，抹平差异。
    """

    impl = sa.DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Any) -> datetime | None:
        """写库前把值统一转成 UTC。

        Raises:
            ValueError: 传入 naive datetime。宁可当场报错，也不猜它是哪个时区 ——
                猜错会让时间悄悄偏移几小时且永远查不出来。
        """
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError(f"拒绝写入 naive datetime: {value!r}，请传带 tzinfo 的值")
        return value.astimezone(UTC)

    def process_result_value(self, value: datetime | None, dialect: Any) -> datetime | None:
        """读库后补齐 tzinfo，保证无论哪个数据库取出来都是 UTC-aware 的。"""
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)
