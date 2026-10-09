"""funauth —— 可复用的登录与注册底座。

## 现在有什么

- 密码登录 + 两级角色（`UserRole.ADMIN` / `GUEST`）
- 邀请码注册：限次、限期、可单独吊销，消耗是原子的
- bcrypt 密码哈希
- 表结构以 **mixin** 形式提供，具体表由宿主声明在自己的 `Base` 上
  （理由见 `funauth.models.mixins` 的模块 docstring）

## 不负责什么

**不依赖任何 web 框架**，也不管 session / cookie / JWT。本包只回答「这个凭据
对不对、这个人是什么角色」，怎么维持登录态是宿主的事（Starlette 的签名 cookie、
Redis session、JWT 都行）。抛出来的是 `AuthError` 子类，宿主自己翻译成状态码。

同样不管事务边界：每个方法收一个 `AsyncSession`，由调用方决定什么时候提交。

## 三步接起来

```python
# 1. 在自己的 Base 上声明表
import sqlalchemy as sa
from funauth.models import InviteCodeMixin, UserMixin

class User(UserMixin, TimestampMixin, Base):
    __tablename__ = "user"
    __table_args__ = (sa.UniqueConstraint("username", name="uq_user_username"),)

class InviteCode(InviteCodeMixin, TimestampMixin, Base):
    __tablename__ = "invite_code"
    __table_args__ = (sa.UniqueConstraint("code", name="uq_invite_code_code"),)

# 2. 建一个单例（放在自己的 services/account.py 之类的绑定模块里）
from funauth import Accounts
accounts = Accounts(user_model=User, invite_model=InviteCode)

# 3. 用
from funauth import BadCredentials
try:
    user = await accounts.authenticate(session, username, password)
except BadCredentials as err:
    raise HTTPException(401, detail=str(err)) from err
```

FastAPI 侧完整的两道门（整站要登录 + 后台要管理员）见 README。

## 往后加登录方式

邮箱验证码、短信验证码、QQ / 微信扫码都按同一形状接：各写一个
`services/*.py` 里的 mixin 挂到 `Accounts` 上，需要存外部身份就再导出一个表
mixin。`User` 表不用动 —— 多种登录方式共用一个账号，靠一张
`(provider, external_id) -> user_id` 的身份表关联，而不是给 `User` 不断加列。
"""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _dist_version

from funauth.enums import UserRole, enum_col
from funauth.errors import (
    AuthError,
    BadCredentials,
    InviteUnusable,
    PermissionDenied,
    UsernameTaken,
)
from funauth.models import InviteCodeMixin, TimestampMixin, UserMixin
from funauth.security import hash_password, verify_password
from funauth.services import Accounts, describe_invite_status, generate_code

try:
    #: 版本号只有 pyproject.toml 一个来源（funbuild 发版时改那里），这里从已安装的
    #: 发行元数据读回来。写成字面量的话迟早和 pyproject 对不上，而且对不上了也没人
    #: 会发现 —— 没有任何东西校验这两处一致。
    __version__ = _dist_version("funauth")
except PackageNotFoundError:  # 源码树里直接 import、没装进环境
    __version__ = "0.0.0.dev0"

__all__ = [
    "Accounts",
    "AuthError",
    "BadCredentials",
    "InviteCodeMixin",
    "InviteUnusable",
    "PermissionDenied",
    "TimestampMixin",
    "UserMixin",
    "UserRole",
    "UsernameTaken",
    "describe_invite_status",
    "enum_col",
    "generate_code",
    "hash_password",
    "verify_password",
]
