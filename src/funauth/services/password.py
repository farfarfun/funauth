"""密码登录与建号。

这是本包目前唯一实现了的登录方式。往后加邮箱验证码、短信验证码、QQ / 微信
扫码，各写一个同形状的 mixin 挂到 `Accounts` 上，共用这里的 `User` 表和
`AccountsBase.get_by_username` 等基础查询。
"""

from __future__ import annotations

import secrets
from collections.abc import Iterable, Sequence
from functools import cache
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from funauth.enums import UserRole
from funauth.errors import (
    BadCredentials,
    LastAdmin,
    PasswordNotSet,
    PermissionDenied,
    UsernameTaken,
)
from funauth.security import hash_password, verify_password
from funauth.services.base import AccountsBase

#: 用户名不存在 / 密码不对 / 账号停用，三种都回这一句。见 `authenticate`。
BAD_CREDENTIALS = "用户名或密码不正确"

#: 降级和停用被「最后一个在用的管理员」护栏拦住时，共用这一句 —— 对操作的人
#: 来说两者的后果是同一个（没人进得去后台了），提示也该是同一句。
LAST_ADMIN = "这是最后一个在用的管理员，请先把别人提成管理员再操作"


@cache
def _dummy_hash() -> str:
    """一个不对应任何密码的 bcrypt 哈希，用来给「用户不存在」那条路径补上等量计算。

    惰性生成而不是模块级常量：`gensalt()` 要几百毫秒，不该让只是
    `import funauth` 的 CLI 或后台任务白付这笔钱。

    也不写死一个字面量哈希：那样 bcrypt 以后调高默认 cost 时，它的耗时就和真实
    哈希对不上，侧信道又回来了。这里用 `hash_password` 生成，cost 永远跟当前
    默认值一致。
    """
    return hash_password(secrets.token_urlsafe(32))


class PasswordMixin(AccountsBase):
    """密码登录、角色判定、建号改密。"""

    async def authenticate(self, session: AsyncSession, username: str, password: str) -> Any:
        """校验用户名密码，返回对应账号。

        **不区分「用户不存在」和「密码不对」**，连「账号已停用」和「这个账号
        没设密码」也归到同一条消息里。分开报的话这个接口就是个用户名枚举器：
        拿字典刷一遍，回「密码不对」的那些就是真实存在的账号，接下来只用对这
        几个爆破密码。

        停用账号也混进去是同一个道理 —— 「这个用户被停用了」同样确认了它存在。
        「这个账号是微信注册的、没有密码」更是如此，它连对方用什么方式登录都
        一起说了。真正需要知道区别的是运维自己，而运维看得到数据库。

        Raises:
            BadCredentials: 上述任一种情况。
        """
        user = await self.get_by_username(session, username)
        if user is None or not user.is_active or not user.password_hash:
            # 对一个假哈希跑一次 bcrypt 再抛，让这条路径和「密码不对」耗时相当。
            # 不补的话消息虽然一样，响应时间差一个数量级（bcrypt 上百毫秒 vs
            # 一次索引查询不到一毫秒），按耗时排序就能把真实账号筛出来 ——
            # 共用消息的努力全白费。
            verify_password(password, _dummy_hash())
            raise BadCredentials(BAD_CREDENTIALS)
        if not verify_password(password, user.password_hash):
            raise BadCredentials(BAD_CREDENTIALS)
        return user

    @staticmethod
    def require_role(user: Any, role: UserRole) -> None:
        """要求 `user` 正好是 `role` 这个角色，不然抛异常。

        用精确相等而不是「大于等于」：`UserRole` 只有两级，而枚举的定义顺序
        不该悄悄决定权限高低（理由见 `UserRole` 的 docstring）。以后真有三级，
        这里要显式写出每级能干什么，而不是靠排序蒙对。

        Raises:
            PermissionDenied: 角色不匹配。
        """
        if user.role != role:
            raise PermissionDenied("需要管理员权限")

    async def create_user(
        self,
        session: AsyncSession,
        username: str,
        password: str | None,
        role: UserRole,
        *,
        commit: bool = True,
    ) -> Any:
        """服务端直接建号，角色由调用方指定。自助注册请走 `register_with_invite`。

        Args:
            password: `None` 表示不开密码登录 —— 建一个只能用外部身份（微信、
                邮箱验证码）登录的账号时传 `None`，之后用 `set_password` 随时
                可以补上。
            commit: 默认提交。传 `False` 只 flush，把提交留给调用方 —— 要把建号
                和宿主自己的写入（建默认工作区之类）放进同一个事务时用。见
                `AccountsBase` 的「事务边界」一节。

        Raises:
            UsernameTaken: 用户名已被占用。
        """
        user = await self._insert(session, username, password, role)
        if commit:
            await session.commit()
            await session.refresh(user)
        return user

    async def set_password(
        self, session: AsyncSession, username: str, password: str, *, commit: bool = True
    ) -> bool:
        """重置密码。用户不存在返回 `False`。

        Args:
            commit: 默认提交，传 `False` 只 flush。
        """
        user = await self.get_by_username(session, username)
        if user is None:
            return False
        user.password_hash = hash_password(password)
        if commit:
            await session.commit()
        else:
            await session.flush()
        return True

    async def set_active(
        self,
        session: AsyncSession,
        username: str,
        active: bool,
        *,
        allow_last_admin: bool = False,
        commit: bool = True,
    ) -> bool:
        """启用 / 停用账号。用户不存在返回 `False`。

        Args:
            allow_last_admin: 停用最后一个在用的管理员时默认会被拦住，传 `True`
                放行。见 `set_role`。
            commit: 默认提交，传 `False` 只 flush。

        Raises:
            LastAdmin: 这一停就没有在用的管理员了。
        """
        user = await self.get_by_username(session, username)
        if user is None:
            return False
        doomed = [user] if self._is_active_admin(user) and not active else []
        await self._guard_last_admin(session, doomed, allow=allow_last_admin)
        user.is_active = active
        if commit:
            await session.commit()
        else:
            await session.flush()
        return True

    async def set_role(
        self,
        session: AsyncSession,
        username: str,
        role: UserRole,
        *,
        allow_last_admin: bool = False,
        commit: bool = True,
    ) -> bool:
        """改账号角色。用户不存在返回 `False`。

        这是「人员管理」页把访客提成管理员、把管理员降回访客的入口。角色以前
        只能在 `create_user` 那一刻定死，改它只能去动 ORM 属性 —— 那样服务层
        就被绕过去了，以后在角色变更上加审计 / 缓存失效也挂不上。

        Args:
            allow_last_admin: 把最后一个在用的管理员降级时默认会被拦住，传
                `True` 放行。给迁移脚本、拆站、或者宿主自己另有后门入口的场合
                留的出口 —— 平时**不要**传，它关掉的正是那条「别把自己锁在
                后台外面」的护栏。
            commit: 默认提交，传 `False` 只 flush。

        Raises:
            LastAdmin: 这一降就没有在用的管理员了。护栏的边界和并发限制见
                `funauth.errors.LastAdmin`。
        """
        user = await self.get_by_username(session, username)
        if user is None:
            return False
        doomed = [user] if self._is_active_admin(user) and role != UserRole.ADMIN else []
        await self._guard_last_admin(session, doomed, allow=allow_last_admin)
        user.role = role
        if commit:
            await session.commit()
        else:
            await session.flush()
        return True

    async def set_role_many(
        self,
        session: AsyncSession,
        usernames: Iterable[str],
        role: UserRole,
        *,
        allow_last_admin: bool = False,
        commit: bool = True,
    ) -> int:
        """一次改一批账号的角色（管理页勾选多行）。返回**实际改到**的条数。

        返回值和传进来的数量对不上，说明名单里有查无此人的 —— 不报错，因为
        管理页上那几行可能刚被别人改过。要较真就自己比对。

        护栏是**整批一起**判的，不是一行一行判：两个账号正好是仅剩的两个在用
        管理员时，逐行判会让它们互相「证明还有人在」，于是一起被降掉。而且判定
        发生在**任何一行被改之前** —— 中途抛异常会留下半批改完的会话，而本包
        的规矩是「回滚始终是调用方的事」，把一个脏会话甩给调用方是陷阱。

        Args:
            allow_last_admin: 同 `set_role`。
            commit: 默认提交，传 `False` 只 flush。名单为空时直接返回 0，
                不碰会话。

        Raises:
            LastAdmin: 这一批降完就没有在用的管理员了。
        """
        wanted = list(dict.fromkeys(usernames))
        if not wanted:
            return 0
        model = self.user_model
        users = list(await session.scalars(select(model).where(model.username.in_(wanted))))
        if not users:
            return 0

        doomed = [u for u in users if self._is_active_admin(u) and role != UserRole.ADMIN]
        await self._guard_last_admin(session, doomed, allow=allow_last_admin)
        for user in users:
            user.role = role
        if commit:
            await session.commit()
        else:
            await session.flush()
        return len(users)

    async def set_username(
        self, session: AsyncSession, username: str, new_username: str, *, commit: bool = True
    ) -> bool:
        """改用户名。用户不存在返回 `False`，改成自己现在这个名字是幂等的。

        主要是给外部身份注册出来的账号用：微信扫码进来的人叫
        `wechat_3f9c1d2a`（本地要一个唯一标识，而微信不给用户名），让他换一个
        人能记住的是常规诉求。

        **改名不会把人踢下线** —— 会话里存的是 `user.id` 不是用户名
        （见 `contrib/fastapi.CookieSessionStore`）。

        Args:
            commit: 默认提交，传 `False` 只 flush。

        Raises:
            UsernameTaken: 新用户名已被别人占用。和 `_insert` 一样这只是预查重，
                **挡不住并发**，真正的保证是宿主在 `username` 上的唯一约束。
        """
        user = await self.get_by_username(session, username)
        if user is None:
            return False
        if new_username == user.username:
            return True
        await self._require_username_free(session, new_username)
        user.username = new_username
        if commit:
            await session.commit()
        else:
            await session.flush()
        return True

    async def change_password(
        self,
        session: AsyncSession,
        username: str,
        old_password: str,
        new_password: str,
        *,
        commit: bool = True,
    ) -> Any:
        """校验旧密码再改密，给「账号与安全」页的自助改密用。

        和 `set_password`（管理员重置，不问旧密码）的区别就在这一次校验上。
        校验直接走 `authenticate`，于是白捡它那套共用消息和时序补偿 ——
        自己再写一遍 `verify_password` 迟早和那边分叉。

        返回账号对象而不是 `bool`（`set_*` 那一族的惯例）：这里查无此人是抛
        异常而不是返回 `False`，没有第二种返回值可言，而调用方通常正好要拿这个
        对象去渲染出参或者记日志。

        **不会让别处已经登录的会话失效。** 本包不持有会话，也没有「密码世代」
        这种列，所以改完密码之后攻击者手上那个 cookie 照样好使。要做到「改密即
        全端下线」得宿主自己来（记一个 `password_changed_at`，会话里存上，每个
        请求比一次）。用户普遍以为改密会踢人，这件事要在界面上说清楚。

        Args:
            commit: 默认提交，传 `False` 只 flush。

        Raises:
            PasswordNotSet: 这个账号从来没设过密码（微信 / 验证码注册的）。
                这里**刻意说实话**：调用方是从会话里拿到用户名的，它已经证明了
                自己就是这个账号，含糊其辞只会让他对着表单反复试一个不存在的
                旧密码。正确的引导是「设置密码」—— 宿主校验完会话直接调
                `set_password`。
            BadCredentials: 旧密码不对（用户不存在 / 账号停用也归这里，共用
                同一句消息）。
        """
        existing = await self.get_by_username(session, username)
        if existing is not None and existing.is_active and not existing.password_hash:
            # 这条路径不补那次假哈希：它不在匿名可达的面上，没有枚举问题，
            # 而真去跑一次 bcrypt 只是白烧 CPU。
            raise PasswordNotSet("这个账号还没有设置过密码，请走「设置密码」")
        user = await self.authenticate(session, username, old_password)
        user.password_hash = hash_password(new_password)
        if commit:
            await session.commit()
        else:
            await session.flush()
        return user

    @staticmethod
    def _is_active_admin(user: Any) -> bool:
        """「在用的管理员」只有这一个定义，护栏的三个调用点共用它。

        停用的管理员不算：他登不进来，拿他给自己壮胆等于护栏形同虚设。
        """
        return user.role == UserRole.ADMIN and user.is_active

    async def _active_admin_count(
        self, session: AsyncSession, *, exclude_ids: Sequence[Any] = ()
    ) -> int:
        """还剩几个在用的管理员，`exclude_ids` 里的不算。"""
        model = self.user_model
        conditions = self._user_where(role=UserRole.ADMIN, is_active=True, keyword=None)
        if exclude_ids:
            conditions.append(model.id.not_in(exclude_ids))
        total = await session.scalar(select(func.count()).select_from(model).where(*conditions))
        return int(total or 0)

    async def _guard_last_admin(
        self, session: AsyncSession, doomed: Sequence[Any], *, allow: bool
    ) -> None:
        """`doomed` 是这次操作之后**不再**是「在用管理员」的那些账号。

        护栏只写这一处，三个调用点各自只负责算出自己的 `doomed` —— 把条件
        抄三遍迟早分叉，而分叉出来的症状是某一条路径能把人锁在后台外面。

        `doomed` 为空（改的是访客、是已停用的号、是 ADMIN -> ADMIN、是
        `set_active(True)`）直接返回，连那次 count 都不发：这些操作一个都不会
        让在用管理员变少，其中「启用」「提升」恰恰是锁死之后唯一的救场路径，
        更不能被自己的护栏挡住。
        """
        if allow or not doomed:
            return
        if await self._active_admin_count(session, exclude_ids=[u.id for u in doomed]) == 0:
            raise LastAdmin(LAST_ADMIN)

    async def _require_username_free(self, session: AsyncSession, username: str) -> None:
        """用户名没被占用就返回，占用了抛 `UsernameTaken`。

        **挡不住并发**（两个请求可以都查到「没占用」然后都写），真正的保证是
        宿主表上的唯一约束。先查一遍只是为了在绝大多数情况下回一句人能看懂的
        「用户名已存在」，而不是把 IntegrityError 原样抛给调用方。
        """
        taken = await session.scalar(
            select(self.user_model.id).where(self.user_model.username == username)
        )
        if taken is not None:
            raise UsernameTaken(f"用户名已存在：{username}")

    async def _insert(
        self, session: AsyncSession, username: str, password: str | None, role: UserRole
    ) -> Any:
        """查重后插入，**不提交**。

        查重的并发限制见 `_require_username_free`。

        Args:
            password: `None` 表示这个账号不开密码登录（外部身份注册出来的账号
                走这条路）。注意 `None` 和空串都落成空的 `password_hash`，而
                `authenticate` 对空哈希一律判失败 —— 不会变成「空密码能登进去」。
        """
        await self._require_username_free(session, username)
        user = self.user_model(
            username=username,
            password_hash=hash_password(password) if password else None,
            role=role,
        )
        session.add(user)
        await session.flush()
        return user
