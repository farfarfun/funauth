"""账号域的异常。

全是 `RuntimeError` 子类，**不是 HTTP 异常** —— 这个包不依赖任何 web 框架，
状态码由调用方翻译（见 README 里 FastAPI 的例子）。异常消息是面向终端用户的
中文，可以直接当 `detail` 回给前端。
"""

from __future__ import annotations


class AuthError(RuntimeError):
    """本包所有异常的基类。调用方可以只捕这一个。"""


class BadCredentials(AuthError):
    """用户名不存在、密码不对、或账号已停用。

    三种情况**共用一条消息**，见 `Accounts.authenticate` 的说明。
    """


class UsernameTaken(AuthError):
    """用户名已被占用。"""


class InviteUnusable(AuthError):
    """邀请码不存在 / 已吊销 / 已过期 / 已用完。

    四种情况共用一条消息：分开报等于把注册接口变成「这个码存不存在」的
    探测器，攻击者能靠枚举问出哪些码是真的、只是暂时用完了。
    """


class PermissionDenied(AuthError):
    """已登录，但角色不够。"""
