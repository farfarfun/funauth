"""`Accounts` 门面。

每种登录方式一个 mixin，`Accounts` 把它们组合起来。现有四条路：

| mixin | 登录方式 | 需要的模型 |
|---|---|---|
| `PasswordMixin` | 用户名 + 密码 | `user_model` |
| `InviteMixin` | 凭邀请码自助注册 | `+ invite_model` |
| `IdentityMixin` | 外部身份（微信 / QQ 扫码） | `+ identity_model` |
| `VerificationMixin` | 邮箱 / 短信验证码 | `+ challenge_model` |

继承链是 `VerificationMixin -> IdentityMixin -> PasswordMixin` 和
`InviteMixin -> PasswordMixin`，因为后面的要复用前面的：凭身份首次登录要建号
（`PasswordMixin._insert`），验证码通过后要走身份那条路（`login_with_identity`）。

**不用的那几条不花钱** —— 对应的 `*_model` 不传就是了，没有空表、没有空列。

再接一家（抖音、飞书、GitHub OAuth……）不需要新 mixin：它们都是「第三方给一个
稳定 id」这个形状，宿主握完手直接调 `login_with_identity`，本包这边只是
`AuthProvider` 多一个成员。真正需要新 mixin 的是**形状**不同的方式，比如
WebAuthn / passkey（要存公钥、要走 challenge-response）。
"""

from funauth.services.base import AccountsBase
from funauth.services.identity import IdentityMixin, default_identity_username
from funauth.services.invite import (
    InviteMixin,
    describe_invite_status,
    generate_code,
)
from funauth.services.password import PasswordMixin
from funauth.services.verification import (
    VerificationMixin,
    generate_verification_code,
    normalize_target,
)


class Accounts(VerificationMixin, InviteMixin, IdentityMixin, PasswordMixin, AccountsBase):
    """账号域的全部操作。宿主建一个单例，别处 import 它。

    ```python
    accounts = Accounts(
        user_model=User,
        invite_model=InviteCode,        # 要邀请码注册才传
        identity_model=Identity,        # 要微信/QQ/邮箱/短信登录才传
        challenge_model=VerificationCode,  # 要邮箱/短信验证码才传
    )
    user = await accounts.authenticate(session, "someone", "pw")
    ```
    """


__all__ = [
    "Accounts",
    "AccountsBase",
    "IdentityMixin",
    "InviteMixin",
    "PasswordMixin",
    "VerificationMixin",
    "default_identity_username",
    "describe_invite_status",
    "generate_code",
    "generate_verification_code",
    "normalize_target",
]
