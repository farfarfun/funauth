"""「用户不存在」和「密码不对」必须耗一样的时间。

两条路径共用一条错误消息（见 `TestAuthenticate` 那边），但如果「用户不存在」直接
返回、不跑 bcrypt，响应时间就差一个数量级：bcrypt 上百毫秒，一次索引查询不到一
毫秒。拿字典刷一遍按耗时排序，真实账号照样被筛出来 —— 共用消息的努力全白费。

这里**不测墙上时钟**（CI 上必然 flaky），测的是「两条路径做了同样次数的哈希
校验」。次数一样是耗时一样的前提，而次数是能稳定断言的。
"""

from __future__ import annotations

import inspect

import pytest

from funauth import BadCredentials, hash_password, verify_password
from funauth.services import password as password_mod

from .conftest import User


@pytest.fixture
def hash_calls(monkeypatch) -> list[str]:
    """记下每次 `verify_password` 拿到的哈希，同时照常执行真逻辑。"""
    calls: list[str] = []
    real = password_mod.verify_password

    def counting(password: str, password_hash: str) -> bool:
        calls.append(password_hash)
        return real(password, password_hash)

    monkeypatch.setattr(password_mod, "verify_password", counting)
    return calls


class TestConstantWork:
    async def test_missing_user_still_burns_a_bcrypt_round(
        self, session, accounts, hash_calls
    ) -> None:
        session.add(User(username="u", password_hash=hash_password("pw")))
        await session.commit()

        for username in ["u", "nobody"]:
            with pytest.raises(BadCredentials):
                await accounts.authenticate(session, username, "wrong")

        assert len(hash_calls) == 2, (
            "「用户不存在」这条路径没做哈希校验，耗时会比「密码不对」短一个数量级，"
            "按响应时间就能枚举出哪些用户名是真的"
        )
        assert len(set(hash_calls)) == 2, "两次该用不同的哈希：一个是真账号的，一个是假的"

    async def test_disabled_user_also_burns_a_round(self, session, accounts, hash_calls) -> None:
        """停用账号走的也是「不存在」那条分支，同样要补上计算。"""
        session.add(User(username="off", password_hash=hash_password("pw"), is_active=False))
        await session.commit()

        with pytest.raises(BadCredentials):
            await accounts.authenticate(session, "off", "pw")

        assert len(hash_calls) == 1

    async def test_the_dummy_hash_is_never_a_valid_password(self) -> None:
        """那个假哈希不能被任何密码撞开，否则就是一条后门。"""
        dummy = password_mod._dummy_hash()
        for guess in ["", "pw", "password", dummy]:
            assert verify_password(guess, dummy) is False

    def test_the_dummy_hash_is_generated_once(self) -> None:
        """同一个进程里只生成一次。

        每次重新 `gensalt()` 不但更慢（于是又和「密码不对」那条路径对不上），
        还等于给匿名请求开了一条 CPU 放大的口子 —— 刷不存在的用户名就能让
        服务端反复做最贵的那步。
        """
        assert password_mod._dummy_hash() is password_mod._dummy_hash()

    def test_authenticate_has_no_early_return_before_hashing(self) -> None:
        """源码级护栏：`authenticate` 里每条 raise 之前都得有一次哈希校验。

        这条断言很糙，但它挡的是最容易复发的改法 —— 有人为了「少查一次库」
        把 `user is None` 那支改回直接 raise，而那种回归在功能测试里看不出来。
        """
        src = inspect.getsource(password_mod.PasswordMixin.authenticate)
        body = src.split('"""')[2]  # 跳过 docstring
        assert body.count("verify_password") == 2, "两条失败路径各要有一次哈希校验"
