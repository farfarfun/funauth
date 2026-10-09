"""现成的 FastAPI 路由与依赖。需要 `pip install "funauth[fastapi]"`。

## funauth 不起服务

这里**没有** `FastAPI()` 实例，也没有 uvicorn 入口 —— 只导出一个装好的
`APIRouter` 和两个依赖注解，由宿主 `include_router` 挂到自己的 app 上，跑在
宿主的进程里。这不是偷懒，是三件事必须共享进程才成立：

1. **事务**。凭邀请码注册要让「扣名额」和「建账号」同生共死，现在它就是一个
   `session.commit()`。跨进程的话这个回滚得靠补偿逻辑或分布式事务，而
   「一张一次性码兑出两个账号」就从一条 SQL 能解决的问题变成要设计的问题。
2. **cookie 同域**。签名 cookie 必须同域才会带上。独立服务要么处理跨域 cookie
   （SameSite / 共享父域 / CORS credentials），要么改走 token。
3. **外键**。`user` 表长在宿主的 `Base` 上，宿主自己的表能正常 FK 引用
   `user.id`。独立服务就得把账号搬进它自己的库，宿主只能存一个没有约束的
   user_id 字符串。

代价是**宿主必须是 Python + FastAPI + SQLAlchemy async**。要给 Go / Node 服务
共用同一批账号，那才需要真起一个服务 —— 届时在 funauth 里加个 `server.py`
建一个 `FastAPI()` 把同一个 router 挂上去即可，现有宿主一行不用改。

## 三个注入点

`make_auth_router` / `make_user_deps` 要宿主告诉它三样东西，别的都不碰：

- `session_dep`：宿主的 DB 会话依赖（事务边界是宿主的事）
- `store`：登录态存哪儿。默认 `CookieSessionStore`（Starlette 签名 cookie），
  走 JWT / Redis 的宿主自己实现 `SessionStore` 协议，十行代码
- `registration_enabled_dep`：注册开关，一个返回 bool 的依赖

## 接起来

```python
from funauth.contrib.fastapi import CookieSessionStore, make_auth_router, make_user_deps

store = CookieSessionStore()
guard = make_user_deps(accounts=accounts, session_dep=SessionDep, store=store)

# 整站门禁 / 运维区，直接当依赖注解用
@router.get("/works")
async def list_works(session: SessionDep, _: guard.current_user): ...

@router.get("/stats")
async def stats(session: SessionDep, _: guard.admin_user): ...

app.include_router(
    make_auth_router(
        accounts=accounts,
        session_dep=SessionDep,
        store=store,
        registration_enabled_dep=RegistrationEnabledDep,
    ),
    prefix="/api/v1",
)
```

宿主还要装上 Starlette 的 `SessionMiddleware`（用默认的 `CookieSessionStore`
时），否则 `request.session` 根本不存在。
"""

import uuid
from dataclasses import dataclass
from typing import Annotated, Any, Protocol, runtime_checkable

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from funauth.enums import UserRole
from funauth.errors import BadCredentials, InviteUnusable, PermissionDenied, UsernameTaken
from funauth.services import Accounts

__all__ = [
    "AuthConfigOut",
    "CookieSessionStore",
    "LoginPayload",
    "RegisterPayload",
    "SessionStore",
    "UserGuards",
    "UserOut",
    "make_auth_router",
    "make_user_deps",
]


# --- 登录态存放 -----------------------------------------------------------------


@runtime_checkable
class SessionStore(Protocol):
    """「这个请求是谁」存在哪儿。

    funauth 不替宿主决定会话方案。签名 cookie、JWT、Redis 都只是这三个方法的
    不同实现，而换方案不该动到任何一个 handler。
    """

    def login(self, request: Request, user_id: str) -> None:
        """登录成功后记下 `user_id`。"""

    def current(self, request: Request) -> str | None:
        """取当前请求的 `user_id`，没有返回 `None`。"""

    def logout(self, request: Request) -> None:
        """清掉登录态。"""


class CookieSessionStore:
    """Starlette `SessionMiddleware` 的签名 cookie。

    宿主必须自己装上那个中间件（`app.add_middleware(SessionMiddleware,
    secret_key=...)`），funauth 不代劳 —— secret_key 怎么来、cookie 叫什么、
    多久过期、`https_only` 开不开，全是宿主的部署决定。

    会话里**只存 user_id，不存角色**。角色每个请求重新查库，这样
    `user disable` 或者降级一个账号之后，他手上那个还没过期的 cookie 立刻失效，
    而不是等到下次登录 —— 把角色塞进 cookie 等于给自己发一张撤不回的通行证。
    """

    def __init__(self, key: str = "user_id") -> None:
        self.key = key

    def login(self, request: Request, user_id: str) -> None:
        request.session[self.key] = user_id

    def current(self, request: Request) -> str | None:
        return request.session.get(self.key)

    def logout(self, request: Request) -> None:
        request.session.clear()


# --- 出入参 ---------------------------------------------------------------------


class LoginPayload(BaseModel):
    username: str
    password: str


class RegisterPayload(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=6, max_length=128)
    #: 必填。没码不能自助注册，这是对公网开放注册的唯一闸门。
    invite_code: str = Field(min_length=1, max_length=32)


class UserOut(BaseModel):
    """默认出参。宿主要多返回字段就自己继承一个传给 `user_out`。"""

    id: uuid.UUID
    username: str
    #: 给前端决定要不要渲染后台入口用。只是省掉一次无意义的点击 —— 真正的
    #: 拦截在 `UserGuards.admin_user`，前端改了这个字段也进不去后台接口。
    role: UserRole

    model_config = {"from_attributes": True}


class AuthConfigOut(BaseModel):
    registration_enabled: bool


# --- 两道门 ---------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class UserGuards:
    """两个依赖注解，直接写在 handler 签名里。

    分两层而不是一个：`current_user` 是**整站门禁**（登录了就放过），
    `admin_user` 在它之上再要求 `ADMIN`。很多站是「进站要口令、后台要管理员」
    这种形状，一个依赖表达不了。
    """

    #: `Annotated[Any, Depends(...)]` —— 已登录且启用，不看角色
    current_user: Any
    #: `Annotated[Any, Depends(...)]` —— 在上一条之上再要求 ADMIN
    admin_user: Any


def make_user_deps(
    *,
    accounts: Accounts,
    session_dep: Any,
    store: SessionStore | None = None,
) -> UserGuards:
    """造出整站门禁 + 管理员这两个依赖。

    Args:
        accounts: 宿主绑好模型类的 `Accounts` 实例。
        session_dep: 宿主的 DB 会话依赖，形如
            `Annotated[AsyncSession, Depends(get_session)]`。传注解而不是裸函数，
            宿主在测试里 `dependency_overrides` 才能照常生效。
        store: 登录态存哪儿，默认 Starlette 签名 cookie。

    Returns:
        `UserGuards`，两个字段都是能直接当注解用的 `Annotated[...]`。

    门禁必须落在后端。纯前端路由守卫挡不住直接 curl 接口 —— 静态文件服务器和
    反向代理层通常没有任何鉴权。
    """
    backend = store or CookieSessionStore()

    async def get_current_user(request: Request, session: session_dep) -> Any:
        user_id = backend.current(request)
        if not user_id:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="请先登录")
        user = await accounts.get_by_id(session, uuid.UUID(user_id))
        if user is None or not user.is_active:
            # 账号被删或被停用，但 cookie 还在。清掉，否则每个请求都要白查一次库。
            backend.logout(request)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="登录已失效，请重新登录"
            )
        return user

    current_user = Annotated[Any, Depends(get_current_user)]

    async def get_admin_user(user: current_user) -> Any:
        """拿 403 而不是 404。

        这个人已经登录了，只是权限不够。装作「没有这个接口」除了让人困惑没有
        别的收益 —— 路由表在前端代码里本来就是公开的。
        """
        try:
            accounts.require_role(user, UserRole.ADMIN)
        except PermissionDenied as err:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(err)) from err
        return user

    admin_user = Annotated[Any, Depends(get_admin_user)]

    return UserGuards(current_user=current_user, admin_user=admin_user)


# --- 路由 -----------------------------------------------------------------------


def make_auth_router(
    *,
    accounts: Accounts,
    session_dep: Any,
    store: SessionStore | None = None,
    registration_enabled_dep: Any = None,
    user_out: type[BaseModel] = UserOut,
    prefix: str = "/auth",
    tags: list[str] | None = None,
) -> APIRouter:
    """造出 `/config`、`/login`、`/logout`、`/me`、`/register` 这一组路由。

    **这些路由全部公开**，不挂任何门禁 —— 否则没登录的人连登录接口都打不开。
    宿主要给其余路由加门禁用 `make_user_deps`。

    Args:
        accounts: 宿主绑好模型类的 `Accounts` 实例。
        session_dep: 宿主的 DB 会话依赖。
        store: 登录态存哪儿，默认 Starlette 签名 cookie。
        registration_enabled_dep: 一个返回 bool 的依赖，形如
            `Annotated[bool, Depends(lambda s: s.registration_enabled)]`。
            `None` 表示注册常开。

            为什么要一个依赖而不是一个 `bool` 或者 `Callable[[], bool]`：宿主的
            配置通常自己就是个依赖（`SettingsDep`），而测试要靠
            `dependency_overrides` 换掉它。直接捕获一个值或闭包会绕过覆盖，
            于是测试里改不动这个开关。
        user_out: 出参模型，默认 `UserOut`（id / username / role）。
        prefix: 路由前缀。宿主再套自己的版本前缀，如
            `include_router(r, prefix="/api/v1")`。
        tags: OpenAPI 标签，默认 `["auth"]`。前端生成 client 时会用到，所以
            留给宿主改。

    Returns:
        装好的 `APIRouter`。`accounts.invite_model` 为 `None` 时**不注册**
        `/register` —— 没有邀请码表就没有自助注册这条路，挂一个必然 500 的
        端点出去不如根本不挂（OpenAPI 里也就不会骗人）。
    """
    backend = store or CookieSessionStore()
    router = APIRouter(prefix=prefix, tags=tags or ["auth"])

    # 注册开关没给就是常开。用一个返回 True 的依赖而不是在 handler 里写 if，
    # 这样两条路径的签名完全一样。
    enabled_dep = (
        registration_enabled_dep
        if registration_enabled_dep is not None
        else Annotated[bool, Depends(lambda: True)]
    )

    def _login(request: Request, user: Any) -> Any:
        """写会话并返回出参。登录和注册成功后都走这里。

        注册完直接进站，不让人再登一次 —— 他刚输过一遍密码。
        """
        backend.login(request, str(user.id))
        return user_out.model_validate(user)

    @router.get("/config", response_model=AuthConfigOut)
    async def get_auth_config(registration_enabled: enabled_dep) -> AuthConfigOut:
        """前端用它决定要不要渲染「注册」入口。"""
        return AuthConfigOut(registration_enabled=registration_enabled)

    @router.post("/login", response_model=user_out)
    async def login(payload: LoginPayload, request: Request, session: session_dep) -> Any:
        """用户名密码登录。

        401 的消息对「用户名不存在 / 密码不对 / 账号停用」三种情况是同一句，
        不要在这里拆开 —— 拆开这个接口就是个用户名枚举器。
        """
        try:
            user = await accounts.authenticate(session, payload.username, payload.password)
        except BadCredentials as err:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(err)) from err
        return _login(request, user)

    @router.post("/logout", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
    async def logout(request: Request) -> None:
        backend.logout(request)

    @router.get("/me", response_model=user_out | None)
    async def me(request: Request, session: session_dep) -> Any:
        """当前登录者，**没登录返回 `null` 而不是 401**。

        前端启动时无条件打这个接口判断「要不要跳登录页」。回 401 会在控制台里
        刷一片红，而「没登录」是这里完全正常的一种答案，不是错误。
        """
        user_id = backend.current(request)
        if not user_id:
            return None
        user = await accounts.get_by_id(session, uuid.UUID(user_id))
        if user is None or not user.is_active:
            backend.logout(request)
            return None
        return user_out.model_validate(user)

    if accounts.invite_model is not None:

        @router.post("/register", response_model=user_out, status_code=status.HTTP_201_CREATED)
        async def register(
            payload: RegisterPayload,
            request: Request,
            session: session_dep,
            registration_enabled: enabled_dep,
        ) -> Any:
            """凭邀请码注册。角色恒为 `GUEST`，这个接口无权指定。

            `InviteUnusable` 的四种成因（不存在 / 已吊销 / 已过期 / 已用完）共用
            一条消息，不要在这里拆开 —— 拆开这个接口就成了「这个码存不存在」的
            探测器。

            用户名撞车时返回 409，而且**已经扣掉的那个名额必须跟着回滚**。这依赖
            宿主的会话依赖在异常时 rollback（FastAPI 的标准写法就是这样），因为
            这里抛出的 `HTTPException` 会一路传到那个依赖的 `except` 里。
            """
            if not registration_enabled:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="注册入口未开放")
            try:
                user = await accounts.register_with_invite(
                    session, payload.username, payload.password, payload.invite_code
                )
            except InviteUnusable as err:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST, detail=str(err)
                ) from err
            except UsernameTaken as err:
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(err)) from err
            return _login(request, user)

    return router
