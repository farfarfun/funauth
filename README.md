# funauth

`funauth` 是一个可复用的登录与注册底座：密码登录、两级角色、邀请码注册。
表结构以 **mixin** 形式提供，具体表长在宿主项目自己的 `Base` 上 —— 一套
`MetaData`、一条迁移链、外键照常写。

## 特性

- 密码登录（bcrypt），用户名不存在 / 密码不对 / 账号停用**共用一句报错**
- 两级角色 `UserRole.ADMIN` / `GUEST`，自助注册出来的账号恒为 `GUEST`
- 邀请码注册：限次、限期、可单独吊销，名额消耗是**一条条件 UPDATE**，并发安全
- 不依赖任何 web 框架，不管 session / cookie / JWT，不管事务边界
- 列类型可移植：PostgreSQL 与 SQLite 上行为一致（时间列始终 UTC-aware）

## 不负责什么

本包只回答「这个凭据对不对、这个人是什么角色」。怎么维持登录态是宿主的事
（Starlette 的签名 cookie、Redis session、JWT 都行）。抛出来的是
`AuthError` 的子类，宿主自己翻译成 HTTP 状态码。

每个方法收一个 `AsyncSession`，什么时候提交由调用方决定 —— 宿主的事务边界各不
相同（FastAPI 一个请求一个 session、CLI 一条命令一个、后台任务一批一个）。

## 环境要求

- Python 3.12 或更高版本
- SQLAlchemy 2.0+（async）

## 安装

```bash
pip install funauth
```

## 快速开始

### 1. 在自己的 Base 上声明表

```python
import sqlalchemy as sa
from sqlalchemy.orm import DeclarativeBase
from funauth.models import InviteCodeMixin, TimestampMixin, UserMixin


class Base(DeclarativeBase): ...


class User(UserMixin, TimestampMixin, Base):
    __tablename__ = "user"
    __table_args__ = (sa.UniqueConstraint("username", name="uq_user_username"),)


class InviteCode(InviteCodeMixin, TimestampMixin, Base):
    __tablename__ = "invite_code"
    __table_args__ = (sa.UniqueConstraint("code", name="uq_invite_code_code"),)
```

唯一约束刻意**不**放进 mixin：约束名会进迁移、进 `ON CONFLICT`，宿主得能看见也能
改名。宿主已经有自己的 `TimestampMixin` 就用自己的，两边 DDL 一致，混用不需要迁移。

### 2. 建一个单例

放在自己的绑定模块里（比如 `myapp/services/account.py`），别处 import 它：

```python
from funauth import Accounts

accounts = Accounts(user_model=User, invite_model=InviteCode)
```

本包不自带表，所以得把宿主的模型类告诉它。用实例持有而不是模块级全局 +
`configure()`：没有全局可变状态，import 顺序无关，同一个进程里也能接两套表
（测试、多租户）。

### 3. 用

```python
from funauth import BadCredentials, UserRole

# 登录
user = await accounts.authenticate(session, "alice", "pw")

# 服务端建管理员
await accounts.create_user(session, "boss", "pw", UserRole.ADMIN)

# 签发邀请码
code = await accounts.issue_invite(session, max_uses=5, expires_in_days=7, note="给张三")
print(code.code)  # K7F2M9QX

# 凭码自助注册（角色恒为 GUEST）
user = await accounts.register_with_invite(session, "newbie", "pw", code.code)
```

## 异常

全是 `RuntimeError` 的子类，**不是** HTTP 异常：

| 异常 | 什么时候抛 | 建议状态码 |
| --- | --- | --- |
| `BadCredentials` | 用户名不存在 / 密码不对 / 账号已停用 | 401 |
| `UsernameTaken` | 用户名已被占用 | 409 |
| `InviteUnusable` | 邀请码不存在 / 已吊销 / 已过期 / 已用完 | 400 |
| `PermissionDenied` | 角色不满足要求 | 403 |

`BadCredentials` 的三种情况和 `InviteUnusable` 的四种情况各自**共用一条消息**，
刻意不区分：分开报的话登录接口就是个用户名枚举器（拿字典刷一遍，回「密码不对」的
那些就是真实存在的账号），注册接口就是个「这个码存不存在」的探测器。真正需要知道
区别的是运维自己，而运维看得到数据库。

## FastAPI：整站门禁 + 后台管理员，两道门

典型需求是「整站要登录才能看，后台还要管理员」。这是两个依赖，不是一个：

```python
from typing import Annotated
from fastapi import Depends, HTTPException, Request, status
from funauth import PermissionDenied, UserRole


async def get_current_user(request: Request, session: SessionDep) -> User:
    """站点门禁：任何已登录且启用的账号都放过。"""
    user_id = request.session.get("user_id")
    if user_id is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="未登录")
    user = await accounts.get_by_id(session, uuid.UUID(user_id))
    if user is None or not user.is_active:
        request.session.clear()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="登录态已失效")
    return user


CurrentUserDep = Annotated[User, Depends(get_current_user)]


async def get_admin_user(user: CurrentUserDep) -> User:
    """后台鉴权：在站点门禁之上再要求 admin。"""
    try:
        accounts.require_role(user, UserRole.ADMIN)
    except PermissionDenied as err:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail=str(err)) from err
    return user


AdminUserDep = Annotated[User, Depends(get_admin_user)]
```

登录和注册这两个端点本身必须保持公开，否则谁都进不来：

```python
@router.post("/auth/login")
async def login(payload: LoginPayload, request: Request, session: SessionDep):
    try:
        user = await accounts.authenticate(session, payload.username, payload.password)
    except BadCredentials as err:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail=str(err)) from err
    request.session["user_id"] = str(user.id)
    return UserOut.model_validate(user)
```

门禁要落在后端。纯前端路由守卫挡不住直接 `curl` 接口 —— 静态文件服务器和反向
代理层通常没有鉴权，前端拦一道等于没拦。

## 邀请码为什么是一条 UPDATE

`consume_invite` 把「还能不能用」整个塞进 WHERE，由数据库裁决：

```sql
UPDATE invite_code SET used_count = used_count + 1, updated_at = :now
 WHERE code = :code AND is_active
   AND used_count < max_uses
   AND (expires_at IS NULL OR expires_at > :now)
```

`rowcount == 0` 就是不可用。先 `SELECT` 判断再 `UPDATE` 的写法在并发下会把一张
`max_uses=1` 的码兑出两个账号：两个请求都读到 `used_count == 0`、都认为还有名额。
这种 bug 在单线程测试里看不出来，所以测试直接盯住发出去的语句（条数必须是 1、
WHERE 里每个守卫都必须在）。

`consume_invite` 自己**不提交**：`register_with_invite` 要让「扣名额」和「建账号」
同生共死 —— 建号那步因为用户名撞车失败时，名额跟着回滚，否则一张码会因为别人
手滑输了个重名用户名而白白少一次，而签发的人完全看不出为什么。

## 往后加登录方式

邮箱验证码、短信验证码、QQ / 微信扫码都按同一形状接：各写一个 `services/*.py`
里的 mixin 挂到 `Accounts` 上，需要存外部身份就再导出一个表 mixin。

`User` 表不用动 —— 多种登录方式共用一个账号，靠一张
`(provider, external_id) -> user_id` 的身份表关联，而不是给 `User` 不断加列。

## 开发

```bash
uv run --group dev pytest -q
uv run --group dev ruff format src tests
uv run --group dev ruff check --fix src tests
```

## 许可证

MIT，见 [LICENSE](LICENSE)。
