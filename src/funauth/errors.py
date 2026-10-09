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


class AccountDisabled(AuthError):
    """凭据对，但账号被停用了。

    和 `BadCredentials` 分开是有意的：密码登录那条路**必须**把停用混进「用户名
    或密码不正确」（否则就是枚举器），但外部身份登录（微信扫码、邮箱验证码）
    没有这个顾虑 —— 能走到这一步说明对方已经证明了自己拥有那个身份，告诉他
    「你的账号被停用了」不泄漏任何他不该知道的事，而含糊其辞只会让他去反复
    重试一个永远不会成功的操作。
    """


class SignupDisabled(AuthError):
    """这个外部身份没绑过账号，而注册入口是关着的。

    和 `AccountDisabled` 一样，这件事可以直说 —— 对方拥有那个身份，而「本站
    目前不开放注册」是公开信息。
    """


class IdentityTaken(AuthError):
    """这个外部身份已经绑在**别的**账号上了。

    绑定接口可以把这个原样回给用户（他知道自己有几个账号），这不是枚举面 ——
    能触发它的前提是你已经证明了自己拥有那个外部身份。
    """


class LastLoginMethod(AuthError):
    """不能解绑：这是该账号最后一种能登进来的方式。

    解掉就变成一个谁都进不去的账号，而用户按下「解绑微信」的时候完全不会想到
    这一层。宁可拦住并提示他先设个密码。
    """


class VerificationFailed(AuthError):
    """验证码不对 / 不存在 / 已过期 / 已用过 / 试错次数超限。

    五种情况共用一条消息，和 `InviteUnusable` 同一个道理 —— 分开报就等于告诉
    爆破方「这个码存在，只是过期了」，等于把搜索空间缩小给他。
    """


class VerificationThrottled(AuthError):
    """发得太频繁了，等一会儿再来。

    这条**必须**存在：短信和邮件都是花钱的外部调用，不限频就是一个既能轰炸
    别人手机、又能刷光你账上余额的接口。
    """
