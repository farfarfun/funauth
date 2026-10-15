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

# 「人员管理」页：列表 + 改角色 + 启停，整组要 ADMIN
app.include_router(
    make_admin_router(accounts=accounts, session_dep=SessionDep, guards=guard),
    prefix="/api/v1",
)
```

宿主还要装上 Starlette 的 `SessionMiddleware`（用默认的 `CookieSessionStore`
时），否则 `request.session` 根本不存在。
"""

import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Annotated, Any, Protocol, runtime_checkable

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field

from funauth.enums import AuthProvider, UserRole
from funauth.errors import (
    AccountDisabled,
    BadCredentials,
    InviteUnusable,
    LastAdmin,
    PermissionDenied,
    SignupDisabled,
    UsernameTaken,
    VerificationFailed,
    VerificationThrottled,
)
from funauth.services import Accounts, normalize_target

__all__ = [
    "AdminUserOut",
    "AuthConfigOut",
    "CodeLoginPayload",
    "CodeRequestPayload",
    "CookieSessionStore",
    "LoginPayload",
    "RegisterPayload",
    "SessionStore",
    "SetActivePayload",
    "SetRolePayload",
    "UserGuards",
    "UserOut",
    "UserPage",
    "make_admin_router",
    "make_auth_router",
    "make_code_login_router",
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
    """默认出参。宿主要多返回字段就自己继承一个传给 `user_out`。

    `id` 写成 `uuid.UUID` 是跟着 `UserMixin` 的主键类型（`PkType = sa.Uuid`）。
    宿主换了主键类型（比如整型自增）就得自己传一个 `user_out`，并且把
    `parse_user_id` 一起换掉 —— 那两处必须对得上。
    """

    id: uuid.UUID
    username: str
    #: 给前端决定要不要渲染后台入口用。只是省掉一次无意义的点击 —— 真正的
    #: 拦截在 `UserGuards.admin_user`，前端改了这个字段也进不去后台接口。
    role: UserRole

    model_config = {"from_attributes": True}


class AdminUserOut(UserOut):
    """管理页的默认出参：在 `UserOut` 上多一个 `is_active`。

    不把它并进 `UserOut`：那个是**登录和 `/me`** 的出参，而「这个号停用没有」
    对当事人没有意义（停用了他根本登不进来），对管理页才有 —— 那张表的第一列
    就是启停开关。
    """

    is_active: bool


class UserPage[OutT: BaseModel](BaseModel):
    """分页出参：`{"total": 123, "items": [...]}`。

    写成泛型而不是在工厂里 `create_model` 现造：现造的类每次调用都叫同一个
    名字，一个 app 里挂两个管理路由就会在 OpenAPI 里撞 schema 名，而宿主拿它
    生成前端 client。泛型参数化出来的名字（`UserPage_AdminUserOut_`）由
    pydantic 自己保证唯一。

    宿主换掉 `user_out` 时这里跟着变成 `UserPage[他那个模型]`，`items` 的类型
    不会和实际返回的对不上。
    """

    #: 命中过滤条件的总数，**不受 limit / offset 影响** —— 分页器要拿它算页数。
    total: int
    items: list[OutT]


class SetRolePayload(BaseModel):
    role: UserRole


class SetActivePayload(BaseModel):
    is_active: bool


class AuthConfigOut(BaseModel):
    registration_enabled: bool


class CodeRequestPayload(BaseModel):
    """「给我发个验证码」。"""

    #: 邮箱或手机号。格式校验留给宿主 —— 它知道自己要不要收手机号、收哪个国家的。
    #: 这里只兜一个长度上限，挡住拿超长字符串灌库的。
    target: str = Field(min_length=3, max_length=128)


class CodeLoginPayload(BaseModel):
    """「这是我收到的验证码」。"""

    target: str = Field(min_length=3, max_length=128)
    code: str = Field(min_length=4, max_length=16)


# --- 会话 -> 账号 ---------------------------------------------------------------


async def _resolve_user(
    *,
    accounts: Accounts,
    session: Any,
    request: Request,
    backend: SessionStore,
    parse_user_id: Callable[[str], Any],
) -> Any | None:
    """把会话里的 user_id 换成账号对象；换不出来就清掉会话、返回 `None`。

    调用方自己决定 `None` 对外是 401 还是 `null`，也自己区分「本来就没登录」和
    「登录过但失效了」—— 前者在调用这里之前一个 `backend.current()` 就能判断。
    """
    raw = backend.current(request)
    if not raw:
        return None
    try:
        user_id = parse_user_id(raw)
    except (ValueError, TypeError, AttributeError):
        # 会话里存的东西根本不是主键的形状：上一套会话方案留下的 cookie、换过
        # 的 secret_key、宿主自己的 SessionStore 存了别的结构。当作「登录失效」
        # 处理 —— 让 `uuid.UUID()` 的 ValueError 原样抛出去只会变成 500，而这
        # 件事的正确答案是「请重新登录」。
        backend.logout(request)
        return None
    user = await accounts.get_by_id(session, user_id)
    if user is None or not user.is_active:
        # 账号被删或被停用，但 cookie 还在。清掉，否则每个请求都要白查一次库。
        backend.logout(request)
        return None
    return user


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
    parse_user_id: Callable[[str], Any] = uuid.UUID,
) -> UserGuards:
    """造出整站门禁 + 管理员这两个依赖。

    Args:
        accounts: 宿主绑好模型类的 `Accounts` 实例。
        session_dep: 宿主的 DB 会话依赖，形如
            `Annotated[AsyncSession, Depends(get_session)]`。传注解而不是裸函数，
            宿主在测试里 `dependency_overrides` 才能照常生效。
        store: 登录态存哪儿，默认 Starlette 签名 cookie。
        parse_user_id: 把会话里的字符串 id 还原成主键值。默认 `uuid.UUID`，对应
            `UserMixin` 的 `PkType`。宿主换了主键类型（比如整型自增）就传 `int`，
            并且把 `user_out` 一起换掉。抛 `ValueError` / `TypeError` 会被当成
            「登录失效」，不会变成 500。

    Returns:
        `UserGuards`，两个字段都是能直接当注解用的 `Annotated[...]`。

    门禁必须落在后端。纯前端路由守卫挡不住直接 curl 接口 —— 静态文件服务器和
    反向代理层通常没有任何鉴权。
    """
    backend = store or CookieSessionStore()

    async def get_current_user(request: Request, session: session_dep) -> Any:
        if not backend.current(request):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="请先登录")
        user = await _resolve_user(
            accounts=accounts,
            session=session,
            request=request,
            backend=backend,
            parse_user_id=parse_user_id,
        )
        if user is None:
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
    parse_user_id: Callable[[str], Any] = uuid.UUID,
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
        parse_user_id: 把会话里的字符串 id 还原成主键值，默认 `uuid.UUID`。
            和 `make_user_deps` 的同名参数含义一样，两处要传一致的。
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
        user = await _resolve_user(
            accounts=accounts,
            session=session,
            request=request,
            backend=backend,
            parse_user_id=parse_user_id,
        )
        if user is None:
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


# --- 管理端：人员管理 -----------------------------------------------------------

#: 列表一次最多给多少条。写死而不是让宿主配：账号表迟早会长到一次拉全表就是
#: 一个慢查询加一个几兆的响应，而那种页面上线时看不出来，半年后才变成事故。
MAX_PAGE_SIZE = 200


def make_admin_router(
    *,
    accounts: Accounts,
    session_dep: Any,
    guards: UserGuards,
    user_out: type[BaseModel] = AdminUserOut,
    allow_self_change: bool = False,
    user_id_type: Any = uuid.UUID,
    prefix: str = "/admin",
    tags: list[str] | None = None,
) -> APIRouter:
    """造出「人员管理」页要的三条路由：列表、改角色、启停。

    ```python
    guard = make_user_deps(accounts=accounts, session_dep=SessionDep, store=store)
    app.include_router(
        make_admin_router(accounts=accounts, session_dep=SessionDep, guards=guard),
        prefix="/api/v1",
    )
    ```

    **这三条全部要求 `ADMIN`**，门禁来自 `guards.admin_user`。

    ## 为什么收整个 `UserGuards` 而不是一个 `admin_user`

    收一个裸依赖的话，宿主手滑传成 `guards.current_user`，造出来的就是一组
    任何登录用户都能改别人角色的接口 —— 没有任何报错，`dependency_overrides`
    也测不出来，是一次彻底的越权。收 `UserGuards` 这个具名类型就不会传错。
    自己另有一套管理员依赖的宿主可以手动拼一个
    `UserGuards(current_user=..., admin_user=...)`。

    `guards` 必须和 `make_auth_router` 用**同一个 `store`**（以及同一个
    `parse_user_id`），否则登录写进去的会话和这里读出来的不是一个地方。

    ## 不能改自己

    默认拦住「把自己降为访客」和「停用自己」—— 手滑点到自己那一行的后果是当场
    失去后台，而这个确认 HTTP 层问不出来。只拦**降级 / 停用**这两个方向：
    把自己设成 ADMIN、启用自己都是无害的空操作，拦了只会让人困惑。

    真要「交接完就自己退下」的宿主传 `allow_self_change=True`，那时还有
    `LastAdmin` 兜着最后一个管理员。

    ## 逃生口不上网

    服务层的 `allow_last_admin` **刻意不暴露成查询参数**。一个 `?force=true`
    就能关掉的安全护栏比没有护栏更糟 —— 前端点着点着就把它加上了。要强行降级
    最后一个管理员，去命令行。

    Args:
        accounts: 宿主绑好模型类的 `Accounts` 实例。
        session_dep: 宿主的 DB 会话依赖。
        guards: `make_user_deps(...)` 的返回值。
        user_out: 出参模型，默认 `AdminUserOut`（比 `UserOut` 多一个
            `is_active`）。换掉它分页出参会自动跟着变成 `UserPage[它]`。
        allow_self_change: 放开「不能改自己」。
        user_id_type: 路径参数 `{user_id}` 的类型，默认 `uuid.UUID`。主键不是
            UUID 的宿主传 `int`，和 `make_user_deps` 的 `parse_user_id`、
            `user_out.id` 三处要一致。
        prefix: 路由前缀，默认 `/admin`。
        tags: OpenAPI 标签，默认 `["admin"]`。

    Returns:
        装好的 `APIRouter`。

    状态码：不是管理员 403、没登录 401（都来自门禁）、查无此人 404、
    改到自己 409、撞上最后一个管理员 409。
    """
    router = APIRouter(prefix=prefix, tags=tags or ["admin"])
    admin_user = guards.admin_user
    page_out = UserPage[user_out]

    async def _fetch(session: Any, user_id: Any) -> Any:
        user = await accounts.get_by_id(session, user_id)
        if user is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="账号不存在")
        return user

    def _refuse_self(actor: Any, target: Any) -> None:
        if not allow_self_change and actor.id == target.id:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="不能改自己，让另一个管理员来操作",
            )

    def _require_changed(changed: bool) -> None:
        """服务层按用户名寻址，这里按 id —— 中间那一瞬间对方可能被改名了。

        改名之后 `set_role` 找不到人会返回 `False`，这时候回 200 等于告诉管理员
        「改好了」而实际什么都没发生。极其罕见，但静默失败是最糟的一种。
        """
        if not changed:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="账号不存在")

    async def _reload(session: Any, user_id: Any, fallback: Any) -> Any:
        """改完之后重新取一遍再序列化。

        服务层提交过了，而提交会 expire 掉会话里的对象（`expire_on_commit` 默认
        就是开的）。直接序列化手上那个实例会触发一次懒加载 —— 在异步会话里那是
        `MissingGreenlet`，也就是一个 500。重查一次最省心，顺带把并发改动也带上。

        重查不到（这一瞬间被别人删了）就退回手上那份，总之不能 500。
        """
        return await accounts.get_by_id(session, user_id) or fallback

    @router.get("/users", response_model=page_out)
    async def list_users(
        session: session_dep,
        _: admin_user,
        role: UserRole | None = None,
        is_active: bool | None = None,
        keyword: Annotated[str | None, Query(max_length=64)] = None,
        offset: Annotated[int, Query(ge=0)] = 0,
        limit: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = 50,
    ) -> Any:
        """分页列出账号。`total` 是命中过滤条件的总数，不受 `limit` 影响。

        `keyword` 是用户名的模糊匹配，不区分大小写；`%` 和 `_` 当字面量处理
        （见 `AccountsBase._user_where`）。限长是为了挡住拿超长字符串换一次
        全表扫描的。
        """
        # 两次查询必须用同一套过滤条件，所以只拼一次 —— 各写一遍迟早分叉，
        # 而分叉的症状是分页器算出 7 页、翻到第 4 页是空的。
        filters = {"role": role, "is_active": is_active, "keyword": keyword}
        total = await accounts.count_users(session, **filters)
        items = await accounts.list_users(session, offset=offset, limit=limit, **filters)
        return page_out(total=total, items=[user_out.model_validate(u) for u in items])

    @router.patch("/users/{user_id}/role", response_model=user_out)
    async def set_role(
        user_id: user_id_type,
        payload: SetRolePayload,
        session: session_dep,
        actor: admin_user,
    ) -> Any:
        """把一个账号提成管理员 / 降回访客。"""
        target = await _fetch(session, user_id)
        if payload.role != UserRole.ADMIN:
            _refuse_self(actor, target)
        try:
            changed = await accounts.set_role(session, target.username, payload.role)
        except LastAdmin as err:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(err)) from err
        _require_changed(changed)
        return user_out.model_validate(await _reload(session, user_id, target))

    @router.patch("/users/{user_id}/active", response_model=user_out)
    async def set_active(
        user_id: user_id_type,
        payload: SetActivePayload,
        session: session_dep,
        actor: admin_user,
    ) -> Any:
        """启用 / 停用一个账号。

        停用而不是删除是这个包的既定设计（见 `UserMixin` 的 docstring）：删了行
        之后会话里存的 user_id 就是悬空引用，而那个 id 以后可能被新账号复用，
        等于把旧会话悄悄接到新账号上。所以这里**没有**删除端点。
        """
        target = await _fetch(session, user_id)
        if not payload.is_active:
            _refuse_self(actor, target)
        try:
            changed = await accounts.set_active(session, target.username, payload.is_active)
        except LastAdmin as err:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(err)) from err
        _require_changed(changed)
        return user_out.model_validate(await _reload(session, user_id, target))

    return router


# --- 验证码登录（邮箱 / 短信）---------------------------------------------------

#: 宿主提供的发送回调：拿到 `(标识, 明文验证码)`，负责把它发出去。
#:
#: 发送通道是宿主的（SES / 阿里云 / 腾讯云，各家 SDK 完全不同），凭据逻辑不是。
#: 这个回调里**不要记日志记明文** —— 那等于把所有人的验证码写进日志系统。
CodeSender = Callable[[str, str], Awaitable[None]]


def make_code_login_router(
    *,
    accounts: Accounts,
    session_dep: Any,
    sender: CodeSender,
    provider: AuthProvider = AuthProvider.EMAIL,
    store: SessionStore | None = None,
    registration_enabled_dep: Any = None,
    user_out: type[BaseModel] = UserOut,
    ttl_seconds: int | None = None,
    min_interval_seconds: int | None = None,
    prefix: str | None = None,
    tags: list[str] | None = None,
) -> APIRouter:
    """造出验证码登录的两条路由：`POST /code`（要码）和 `POST /login`（用码登录）。

    同一个工厂同时服务邮箱和短信 —— 两者在本包里是同一条链路，只有 `provider`
    和发送通道不同。要两种都上就调两次，各挂一个 prefix：

    ```python
    app.include_router(make_code_login_router(
        accounts=accounts, session_dep=SessionDep, store=store,
        provider=AuthProvider.EMAIL, sender=send_email,
    ))   # -> /auth/email/code, /auth/email/login
    app.include_router(make_code_login_router(
        accounts=accounts, session_dep=SessionDep, store=store,
        provider=AuthProvider.PHONE, sender=send_sms,
    ))   # -> /auth/phone/code, /auth/phone/login
    ```

    ## 这里没有用户名枚举面

    `POST /code` 对**任何**标识都照发，不管它注册过没有 —— 因为验证码登录本身
    就兼注册，「没注册」不是一种失败。所以这个接口不像密码登录那样需要含糊其辞。

    注册开关关着时也照发，只在 `POST /login` 那步回 403。看起来绕，但另一种做法
    （没注册就不发）等于把「这个邮箱注册过没有」做成了一个公开查询接口。而在
    `/login` 那步泄漏只泄漏给能收到这封邮件的人 —— 也就是那个邮箱的主人。

    Args:
        sender: 发送回调，见 `CodeSender`。
        provider: `AuthProvider.EMAIL` 或 `PHONE`。也决定默认 prefix。
        ttl_seconds / min_interval_seconds: 透传给 `issue_verification_code`，
            `None` 用包里的默认值（10 分钟 / 60 秒）。短信比邮件贵，真上短信的
            时候建议把间隔调大。
        prefix: 默认 `/auth/{provider}`，例如 `/auth/email`。

    Returns:
        装好的 `APIRouter`。

    发送失败时会把刚签发的那条记录**删掉**再回 502：不删的话用户既没收到码、
    又要被限频挡 60 秒，而他什么都没做错。
    """
    backend = store or CookieSessionStore()
    router = APIRouter(prefix=prefix or f"/auth/{provider.value}", tags=tags or ["auth"])

    enabled_dep = (
        registration_enabled_dep
        if registration_enabled_dep is not None
        else Annotated[bool, Depends(lambda: True)]
    )

    #: 只把调用方显式给了的值透传下去，`None` 的让服务层用自己的默认值 ——
    #: 在这里把默认值抄一遍迟早和那边对不上。
    issue_kwargs: dict[str, int] = {}
    if ttl_seconds is not None:
        issue_kwargs["ttl_seconds"] = ttl_seconds
    if min_interval_seconds is not None:
        issue_kwargs["min_interval_seconds"] = min_interval_seconds

    @router.post("/code", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
    async def request_code(payload: CodeRequestPayload, session: session_dep) -> None:
        """签发一个验证码并发出去。

        429 带 `Retry-After`，前端可以直接拿它做倒计时，不用自己猜。
        """
        try:
            code, record = await accounts.issue_verification_code(
                session, provider, payload.target, **issue_kwargs
            )
        except VerificationThrottled as err:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=str(err),
                headers={"Retry-After": str(min_interval_seconds or 60)},
            ) from err

        try:
            # 发给规整后的标识，和落库那个保持一致 —— 用户输了 `Me@Example.com`
            # 而库里存的是小写，发信地址用哪个都能到，但日志里两处对不上很难查。
            await sender(normalize_target(provider, payload.target), code)
        except Exception as err:
            # 码已经提交了。发不出去就把它删掉，否则用户既没收到码、又要被限频
            # 挡住重发 —— 而这完全是我们这边的故障。
            await session.delete(record)
            await session.commit()
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY, detail="验证码发送失败，请稍后重试"
            ) from err

    @router.post("/login", response_model=user_out)
    async def login_with_code(
        payload: CodeLoginPayload,
        request: Request,
        session: session_dep,
        registration_enabled: enabled_dep,
    ) -> Any:
        """用验证码登录，没注册过就当场开一个账号（角色恒为 `GUEST`）。

        `VerificationFailed` 的五种成因共用一条消息，不要在这里拆开 —— 拆开就
        等于告诉爆破方「这个码是对的，只是过期了」。
        """
        try:
            user, _created = await accounts.login_with_code(
                session,
                provider,
                payload.target,
                payload.code,
                allow_signup=registration_enabled,
            )
        except VerificationFailed as err:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(err)) from err
        except SignupDisabled as err:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(err)) from err
        except AccountDisabled as err:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(err)) from err
        backend.login(request, str(user.id))
        return user_out.model_validate(user)

    return router
