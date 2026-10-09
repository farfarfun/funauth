"""funauth —— 可复用的登录与注册底座。

## 现在有什么

四条登录路，按需取用（不用的那条不传对应模型即可，没有空表也没有空列）：

- **密码登录** + 两级角色（`UserRole.ADMIN` / `GUEST`），bcrypt 哈希
- **邀请码注册**：限次、限期、可单独吊销，消耗是原子的
- **外部身份**（微信 / QQ 扫码）：`(provider, external_id) -> user_id` 一张表，
  握手由宿主做，本包只管「这个身份是哪个账号」
- **邮箱 / 短信验证码**：签发、哈希、原子消耗、试错限次、发送限频都在包内，
  宿主只提供一个「把这段文字发出去」的回调

一个账号可以同时挂多种方式（设了密码、绑了微信、验证过邮箱），`User` 表不会
因为多接一家而加列。

表结构以 **mixin** 形式提供，具体表由宿主声明在自己的 `Base` 上（理由见
`funauth.models.mixins` 的模块 docstring）。

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

## 再接一家第三方

抖音、飞书、GitHub OAuth 这些**不需要**改本包：它们都是「第三方给一个稳定
id」这个形状，宿主握完手直接调 `Accounts.login_with_identity`，本包这边只是
`AuthProvider` 多一个成员，没有任何 DDL 变化。

真正需要新 mixin 的是**形状**不同的方式，比如 WebAuthn / passkey（要存公钥、
要走 challenge-response）。那时候照 `services/identity.py` 的样子再写一个挂到
`Accounts` 上，`User` 表同样不用动。
"""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _dist_version

from funauth.enums import AuthProvider, UserRole, enum_col
from funauth.errors import (
    AccountDisabled,
    AuthError,
    BadCredentials,
    IdentityTaken,
    InviteUnusable,
    LastLoginMethod,
    PermissionDenied,
    SignupDisabled,
    UsernameTaken,
    VerificationFailed,
    VerificationThrottled,
)
from funauth.models import (
    ExternalIdentityMixin,
    InviteCodeMixin,
    TimestampMixin,
    UserMixin,
    VerificationCodeMixin,
)
from funauth.security import hash_password, verify_password
from funauth.services import (
    Accounts,
    default_identity_username,
    describe_invite_status,
    generate_code,
    generate_verification_code,
    normalize_target,
)

try:
    #: 版本号只有 pyproject.toml 一个来源（funbuild 发版时改那里），这里从已安装的
    #: 发行元数据读回来。写成字面量的话迟早和 pyproject 对不上，而且对不上了也没人
    #: 会发现 —— 没有任何东西校验这两处一致。
    __version__ = _dist_version("funauth")
except PackageNotFoundError:  # 源码树里直接 import、没装进环境
    __version__ = "0.0.0.dev0"

__all__ = [
    "AccountDisabled",
    "Accounts",
    "AuthError",
    "AuthProvider",
    "BadCredentials",
    "ExternalIdentityMixin",
    "IdentityTaken",
    "InviteCodeMixin",
    "InviteUnusable",
    "LastLoginMethod",
    "PermissionDenied",
    "SignupDisabled",
    "TimestampMixin",
    "UserMixin",
    "UserRole",
    "UsernameTaken",
    "VerificationCodeMixin",
    "VerificationFailed",
    "VerificationThrottled",
    "default_identity_username",
    "describe_invite_status",
    "enum_col",
    "generate_code",
    "generate_verification_code",
    "hash_password",
    "normalize_target",
    "verify_password",
]
