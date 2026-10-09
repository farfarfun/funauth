"""表结构以 **mixin** 形式提供，具体表由宿主项目声明。

## 为什么不直接导出现成的模型类

一个 declarative 模型必须绑在某个 `Base`（也就是某个 `MetaData`）上。如果本包
自带 `Base`，宿主项目的库里就有两套 `MetaData`：

- `Base.metadata.create_all()` 建不出本包的表，宿主的测试夹具得额外记得建一遍；
- Alembic 的 `target_metadata` 得写成列表，否则 autogenerate 会兴冲冲地生成
  「DROP TABLE user」—— 它看不见那张表的定义，只看见库里多了一张表；
- 宿主自己的表想外键引用 `user.id` 时跨 `MetaData`，得退化成字符串引用。

导出 mixin 就没这些问题：表长在宿主的 `Base` 上，一套 `MetaData`、一条迁移链、
外键照常写。代价是宿主要自己写一行类声明和 `__table_args__`，很便宜。

```python
from funauth.models import InviteCodeMixin, UserMixin

class User(UserMixin, TimestampMixin, Base):
    __tablename__ = "user"
    __table_args__ = (sa.UniqueConstraint("username", name="uq_user_username"),)
```

唯一约束刻意**不**放进 mixin：约束名进迁移、进 `ON CONFLICT`，宿主得能看见也能
改名（已经建好的库里那个名字是什么样就得是什么样，不能由本包的版本决定）。

## 时间列

`TimestampMixin` 这里也给了一份，但宿主已经有自己的就用自己的 —— 两边 DDL
一致（都是 `DateTime(timezone=True)`），混用不需要迁移。
"""

from __future__ import annotations

import uuid
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from funauth.enums import UserRole, enum_col
from funauth.models.types import PkType, UTCDateTime, utcnow, uuid7


class TimestampMixin:
    """创建 / 更新时间。默认值在 Python 侧生成，不依赖数据库函数。"""

    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime, default=utcnow, nullable=False, index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        UTCDateTime, default=utcnow, onupdate=utcnow, nullable=False
    )


class UserMixin:
    """登录账号：用户名 + bcrypt 密码哈希 + 角色 + 启用标记。

    不存明文密码，也不做可逆加密。停用走 `is_active` 而不是删除行 —— 否则
    session / token 里存的 user_id 会变成悬空引用，而那个 id 以后可能被别的
    新账号复用，等于把旧会话悄悄接到新账号上。
    """

    id: Mapped[uuid.UUID] = mapped_column(PkType, primary_key=True, default=uuid7)
    username: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    #: bcrypt 哈希（含盐）
    password_hash: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    #: 默认取 `GUEST` 而不是 `ADMIN`：漏传时往最小权限掉，而不是凭空多出一个
    #: 管理员。要建管理员必须显式写出来（`Accounts.create_user`）。
    role: Mapped[UserRole] = mapped_column(
        enum_col(UserRole, length=16), nullable=False, default=UserRole.GUEST
    )
    is_active: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=True)


class InviteCodeMixin:
    """一张注册邀请码：码值 + 可用次数 + 过期时间 + 启用标记。

    「还能不能用」是三个条件的合取，判定只许写在 `Accounts.consume_invite` 的
    那条条件 UPDATE 里 —— 在别处重新拼一遍等于埋一个会和它悄悄分叉的副本。
    """

    id: Mapped[uuid.UUID] = mapped_column(PkType, primary_key=True, default=uuid7)
    #: 码值本身。只取大写字母和数字、去掉易混的 0O1Il，方便口头/截图转述
    code: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    #: 总共能换出几个账号
    max_uses: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=1)
    #: 已经换出去几个。只由 `consume_invite` 的条件 UPDATE 原子递增
    used_count: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=0)
    #: 空 = 永不过期
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    #: 吊销走标记而不是删行 —— 和 `UserMixin.is_active` 同一个理由：保留「这张码
    #: 换出去过几个账号」的痕迹，删掉就查不出来了
    is_active: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=True)
    #: 备注，给签发的人自己记「这张给谁的」
    note: Mapped[str | None] = mapped_column(sa.Text)
