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

**本包的逻辑不读也不写 `created_at` / `updated_at`**，所以时间列整个不要也能跑
（只有 `InviteMixin.list_invites` 按 `created_at` 排序，不挂时间列就别用它，或者
自己按 `id` 排 —— `uuid7` 的字典序就是生成顺序）。

`updated_at` 的推进交给列自己的 `onupdate`，本包不在 UPDATE 语句里手写它。写进
`.values()` 看着更省事，但那样 `consume_invite` / `revoke_invite` 就隐式要求
邀请码表必须有一个**正好叫** `updated_at` 的列 —— 宿主只继承 `InviteCodeMixin`
不继承 `TimestampMixin`、或者自己那套时间列叫 `modified_at`，就会在运行时炸。
"""

from __future__ import annotations

import uuid
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from funauth.enums import AuthProvider, UserRole, enum_col
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

    一个账号可以挂多种登录方式（密码、微信、邮箱验证码……），后者存在
    `ExternalIdentityMixin` 那张表里，**不往这张表加列** —— 否则每接一家就要
    一条迁移，而且「这个人绑了几个微信」这种问题答不出来。
    """

    id: Mapped[uuid.UUID] = mapped_column(PkType, primary_key=True, default=uuid7)
    username: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    #: bcrypt 哈希（含盐）。**可空** —— 微信扫码 / 邮箱验证码注册出来的账号没有
    #: 密码，空值表示「这个账号没开密码登录」，不表示「密码是空的」。
    #: `PasswordMixin.authenticate` 会把它和「用户不存在」归到同一种失败里。
    password_hash: Mapped[str | None] = mapped_column(sa.String(128))
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


class ExternalIdentityMixin:
    """一个外部身份 -> 一个本地账号。

    ## 为什么是一张表而不是 `User` 上的几列

    「给 User 加个 wechat_openid 列」在只接一家的时候看着更省事，但：

    - 再接 QQ、再接手机号，每次都是一条迁移，而且列会越来越多、绝大多数是空的；
    - 一个人绑两个微信（个人号 + 工作号）表达不了；
    - 「这个 openid 是谁」要全表扫 User，而这是登录路径上最热的查询。

    一张 `(provider, external_id) -> user_id` 的表把这些都解决了，接新的一家
    只是多一个枚举成员，不动任何 DDL。

    ## 宿主要自己加的约束

    ```python
    class Identity(ExternalIdentityMixin, TimestampMixin, Base):
        __tablename__ = "identity"
        __table_args__ = (
            sa.UniqueConstraint("provider", "external_id",
                                name="uq_identity_provider_external"),
            sa.ForeignKeyConstraint(["user_id"], ["user.id"],
                                    name="fk_identity_user", ondelete="CASCADE"),
        )
    ```

    那条唯一约束**不是装饰**：它是「两个请求同时拿同一个 openid 进来」这个竞态
    的唯一真实保障。`IdentityMixin.login_with_identity` 的「查不到就建」挡不住
    并发（两边都查到「没有」然后都建），靠的就是这里撞约束之后重查 —— 和
    `PasswordMixin._insert` 是同一套路。

    外键和唯一约束一样留给宿主：`sa.ForeignKey("user.id")` 里那个 `"user"` 是
    宿主定的表名，写进 mixin 就等于本包替所有宿主决定了表叫什么。
    """

    id: Mapped[uuid.UUID] = mapped_column(PkType, primary_key=True, default=uuid7)
    provider: Mapped[AuthProvider] = mapped_column(
        enum_col(AuthProvider, length=32), nullable=False
    )
    #: 第三方那边的**稳定**标识：微信 unionid（不是 openid —— openid 跨应用会变）、
    #: QQ openid、本系统验证过的邮箱 / 手机号。
    #: 不要存昵称：昵称能重复、能带 emoji、能随时改，当不了唯一键。
    external_id: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    user_id: Mapped[uuid.UUID] = mapped_column(PkType, nullable=False, index=True)
    #: 展示用的附带信息（昵称、头像 URL、第三方那边的邮箱）。只用来显示，
    #: **不参与任何判定** —— 它来自外部，随时可能被对方改成任何值。
    display_name: Mapped[str | None] = mapped_column(sa.String(128))


class VerificationCodeMixin:
    """发给某个标识（邮箱 / 手机号）的一次性验证码。

    形状和 `InviteCodeMixin` 刻意保持一致（限期 + 一次性 + 原子消耗），消耗同样
    只许写成一条带守卫的 UPDATE。

    和邀请码的两个区别：

    1. **存哈希不存明文**。这是凭据，和 `password_hash` 同等对待 —— 库被读一眼
       就等于所有在途验证码泄漏，而验证码能直接登进账号。
    2. **有试错计数**。6 位数字只有 100 万种组合，不限次就是个在线爆破靶子
       （邀请码有 32^8 种，而且本来就是要发给人的）。

    自带 `issued_at` 而不是借 `TimestampMixin.created_at`：发送限频要读这个时间，
    是本包的**逻辑**依赖，不能指望宿主一定挂了时间列（见本模块「时间列」一节）。
    """

    id: Mapped[uuid.UUID] = mapped_column(PkType, primary_key=True, default=uuid7)
    provider: Mapped[AuthProvider] = mapped_column(
        enum_col(AuthProvider, length=32), nullable=False
    )
    #: 发给谁：邮箱地址或手机号。查询热点，建索引
    target: Mapped[str] = mapped_column(sa.String(128), nullable=False, index=True)
    #: bcrypt 哈希。明文只在签发那一刻存在于内存里，返回给宿主发出去之后就没了
    code_hash: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    issued_at: Mapped[datetime] = mapped_column(
        UTCDateTime, nullable=False, default=utcnow, index=True
    )
    #: 必填，没有「永不过期的验证码」这种东西
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    #: 非空表示已经用掉了（或被新签发的码顶掉了）。一次性靠这列的条件 UPDATE 保证
    consumed_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    #: 试错次数。超过上限直接作废，不等过期
    attempts: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=0)
