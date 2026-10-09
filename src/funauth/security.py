"""密码哈希。

直接用 `bcrypt`，不引入 passlib —— passlib 已多年未发版，对 bcrypt 4.x 的
`__about__` 变更没跟上，社区里一堆关于它报 warning/崩溃的 issue。bcrypt 库
本身的 API 就两个函数，没有再包一层的必要。
"""

from __future__ import annotations

import bcrypt


def hash_password(password: str) -> str:
    """对明文密码做 bcrypt 哈希。

    Args:
        password: 用户输入的明文密码。

    Returns:
        可直接落库的 bcrypt 哈希字符串（含算法标识与随机 salt）。
    """
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str | None) -> bool:
    """校验明文密码是否与已存储的哈希匹配。

    Args:
        password: 登录时用户输入的明文密码。
        password_hash: `hash_password` 生成并落库的哈希值。允许是 `None` 或空串
            —— 外部身份注册出来的账号（微信扫码、邮箱验证码）压根没有密码。

    Returns:
        匹配返回 `True`。以下情况一律返回 `False`，**不抛异常**：密码不匹配、
        `password_hash` 为空（该账号没开密码登录）、`password_hash` 不是合法的
        bcrypt 格式（例如历史迁移遗留的明文）。

        校验失败只该是一个布尔结果。让它抛出去的话，调用方每多一种脏数据就多
        一个 500，而这里能给出的正确答案始终是「这个凭据不对」。
    """
    if not password_hash:
        return False
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except (ValueError, TypeError, AttributeError):
        # 哈希格式不对（库迁移时手滑存了明文）、或者根本不是字符串：当作校验
        # 失败而不是 500
        return False
