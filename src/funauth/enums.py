"""枚举与枚举列。"""

from __future__ import annotations

from enum import StrEnum

import sqlalchemy as sa


def enum_col(py_enum: type[StrEnum], length: int = 32) -> sa.Enum:
    """把 Python StrEnum 映射成 VARCHAR，不生成数据库侧的 CHECK 约束。

    不生成 CHECK 是刻意的：枚举加一个成员就要写一条迁移去改约束，而这类
    枚举（登录方式、角色）本来就是会持续扩张的。
    """
    return sa.Enum(
        py_enum,
        native_enum=False,
        create_constraint=False,
        length=length,
        values_callable=lambda e: [m.value for m in e],
    )


class UserRole(StrEnum):
    """账号角色，只有两级。

    `GUEST` 是自助注册能拿到的唯一角色；`ADMIN` 只能由服务端显式创建
    （`Accounts.create_user`）。

    两级之间**不做数值比较**，判定一律写 `role != ADMIN` 这种精确相等 ——
    以后真要加第三级（比如只读审计员），枚举的定义顺序不该悄悄决定它的权限。
    """

    ADMIN = "admin"
    GUEST = "guest"
