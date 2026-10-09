"""`Accounts` 门面。

各登录方式一个 mixin，按需组合。目前只有密码登录（`PasswordMixin`）和邀请码
注册（`InviteMixin`）；邮箱验证码、短信验证码、QQ / 微信扫码往后按同一形状加
——各自一个 mixin + 各自的 mixin 表，挂上来即可，`User` 表不用动。
"""

from funauth.services.base import AccountsBase
from funauth.services.invite import (
    InviteMixin,
    describe_invite_status,
    generate_code,
)
from funauth.services.password import PasswordMixin


class Accounts(InviteMixin, PasswordMixin, AccountsBase):
    """账号域的全部操作。宿主建一个单例，别处 import 它。

    ```python
    accounts = Accounts(user_model=User, invite_model=InviteCode)
    user = await accounts.authenticate(session, "someone", "pw")
    ```
    """


__all__ = [
    "Accounts",
    "AccountsBase",
    "InviteMixin",
    "PasswordMixin",
    "describe_invite_status",
    "generate_code",
]
