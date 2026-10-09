# funauth

`funauth` 是一个可复用的登录与注册底座：密码登录、两级角色、邀请码注册、
微信 / QQ 扫码、邮箱 / 短信验证码。表结构以 **mixin** 形式提供，具体表长在宿主
项目自己的 `Base` 上 —— 一套 `MetaData`、一条迁移链、外键照常写。

版本变化见 [CHANGELOG.md](CHANGELOG.md)。

## 目录

- [特性](#特性) · [不负责什么](#不负责什么) · [环境要求](#环境要求) ·
  [安装](#安装)
- [快速开始](#快速开始)：[建表](#1-在自己的-base-上声明表) ·
  [建单例](#2-建一个单例) · [用](#3-用)
- 登录方式：[外部身份（微信 / QQ）](#外部身份微信--qq-扫码) ·
  [邮箱 / 短信验证码](#邮箱--短信验证码)
- [异常与建议状态码](#异常)
- [FastAPI](#fastapi)：[验证码路由](#验证码登录的路由) ·
  [两道门](#整站门禁--后台管理员两道门) · [会话方案](#会话里只存-user_id) ·
  [为什么不起独立服务](#funauth-不起服务)
- 设计说明：[邀请码为什么是一条 UPDATE](#邀请码为什么是一条-update) ·
  [往后再加登录方式](#往后再加登录方式)
- [从 0.2.x 升级](#从-02x-升级) · [源码导览](#源码导览) · [开发](#开发)

## 特性

四条登录路，按需取用 —— 不用的那条不传对应模型即可，没有空表也没有空列：

| 方式 | 入口 | 需要的模型 |
|---|---|---|
| 用户名 + 密码 | `authenticate` | `user_model` |
| 邀请码自助注册 | `register_with_invite` | `+ invite_model` |
| 微信 / QQ 扫码 | `login_with_identity` | `+ identity_model` |
| 邮箱 / 短信验证码 | `login_with_code` | `+ challenge_model` |

一个账号可以同时挂多种方式（设了密码、绑了微信、验证过邮箱），`User` 表不会
因为多接一家而加列。

- 密码登录（bcrypt）：用户名不存在 / 密码不对 / 账号停用 / **没设过密码**共用
  一句报错，而且**耗时一致**（失败路径也跑一次 bcrypt，不然按响应时间就能枚举）
- 两级角色 `UserRole.ADMIN` / `GUEST`，所有自助入口产出的账号恒为 `GUEST`
- 邀请码：限次、限期、可单独吊销，名额消耗是**一条条件 UPDATE**，并发安全
- 外部身份：`(provider, external_id) -> user_id` 一张表，**绝不按邮箱自动合并
  账号**（那是个账号接管漏洞，见下文）
- 验证码：存哈希不存明文、一次性原子消耗、试错限次（计数**活过 rollback**）、
  发送限频（短信是花钱的）
- 不依赖任何 web 框架，不管 session / cookie / JWT
- 列类型可移植：PostgreSQL 与 SQLite 上行为一致（时间列始终 UTC-aware）
- 可选的 FastAPI 适配（`funauth[fastapi]`）：现成端点 + 整站门禁 / 管理员两道门，
  宿主一行 `include_router` 接上

## 不负责什么

本包只回答「这个凭据对不对、这个人是什么角色」。怎么维持登录态是宿主的事
（Starlette 的签名 cookie、Redis session、JWT 都行）。抛出来的是
`AuthError` 的子类，宿主自己翻译成 HTTP 状态码。

每个方法收一个 `AsyncSession`，本包不自己建、不自己关 —— 宿主的会话生命周期各不
相同（FastAPI 一个请求一个、CLI 一条命令一个、后台任务一批一个）。

提交这件事分四档，不要靠猜：

- **公开写方法**默认 `commit=True` 自己提交；传 `commit=False` 则只 flush，提交
  留给你 —— 要把账号操作和你自己的写入（建默认工作区之类）凑进**同一个事务**时
  用这个。这一档包括 `create_user`、`set_password`、`set_active`、`issue_invite`、
  `revoke_invite`、`register_with_invite`、`login_with_identity`、`link_identity`、
  `unlink_identity`、`issue_verification_code`、`login_with_code`。
- **`consume_invite` 从不提交**，也刻意没有 `commit` 参数（理由见下文「邀请码
  为什么是一条 UPDATE」）。
- **`verify_code` 是个例外**：它在校验结果出来之前就把试错计数单独提交掉，所以
  即使在失败路径上它也会提交一次。这是安全权衡，不是疏漏 —— 理由见下文
  「试错计数为什么单独提交」。因此请在请求早期调它。
- **回滚始终是调用方的事。** 本包抛异常时不 rollback —— 会话是你的，里面可能还
  包着你自己的写入。FastAPI 宿主的标准写法正好覆盖这件事：

```python
async def get_session() -> AsyncIterator[AsyncSession]:
    async with maker() as s:
        try:
            yield s
        except Exception:
            await s.rollback()
            raise
```

会话方案和状态码映射在 `funauth.contrib.fastapi` 里有一套现成的（见下文），但那是
**可选的 extra**，核心这层不认识 HTTP。

## 环境要求

- Python 3.12 或更高版本
- SQLAlchemy 2.0+（async）

## 安装

```bash
pip install funauth

# 要用现成的 FastAPI 路由与依赖
pip install "funauth[fastapi]"
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

要微信 / QQ 扫码或邮箱 / 短信验证码，再加这两张：

```python
from funauth.models import ExternalIdentityMixin, VerificationCodeMixin


class Identity(ExternalIdentityMixin, TimestampMixin, Base):
    __tablename__ = "identity"
    __table_args__ = (
        sa.UniqueConstraint("provider", "external_id", name="uq_identity_provider_external"),
        sa.ForeignKeyConstraint(
            ["user_id"], ["user.id"], name="fk_identity_user", ondelete="CASCADE"
        ),
    )


class VerificationCode(VerificationCodeMixin, TimestampMixin, Base):
    __tablename__ = "verification_code"
```

`(provider, external_id)` 那条唯一约束**不是装饰**：它是「两个请求同时拿同一个
openid 进来」唯一的真实保障。`login_with_identity` 的「查不到就建」挡不住并发，
靠的就是撞上它之后重查。外键同样留给宿主 —— `"user.id"` 里那个表名是宿主定的。

### 2. 建一个单例

放在自己的绑定模块里（比如 `myapp/services/account.py`），别处 import 它：

```python
from funauth import Accounts

accounts = Accounts(
    user_model=User,
    invite_model=InviteCode,  # 要邀请码注册才传
    identity_model=Identity,  # 要微信/QQ/邮箱/短信登录才传
    challenge_model=VerificationCode,  # 要邮箱/短信验证码才传
)
```

后三个不传就是不启用那条路，对应方法调了会直接炸 —— 刻意不做优雅降级，否则
「忘了配」会变成登录相关的静默失败，而那是最糟的一种。

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

## 外部身份（微信 / QQ 扫码）

```python
from funauth import AuthProvider

# 宿主先和第三方握完手，拿到一个稳定 id
openid = await my_wechat_client.exchange(code)

# funauth 只管「这个身份是哪个账号」，没绑过就当场开一个
user, created = await accounts.login_with_identity(
    session, AuthProvider.WECHAT, openid, display_name=nickname
)

# 已登录用户主动绑定 / 解绑
await accounts.link_identity(session, user, AuthProvider.WECHAT, openid)
await accounts.unlink_identity(session, user, AuthProvider.WECHAT)
```

**握手不在本包里。** code 换 token、state 防 CSRF、各家不同的回调格式、PC 扫码和
公众号授权的差异 —— 这些要 httpx、要 appid/secret、要跟着平台文档变。本包核心层
只依赖 sqlalchemy 和 bcrypt，把平台 SDK 拖进来，每个只用密码登录的宿主都得跟着背。

再接一家（抖音、飞书、GitHub OAuth）**不需要改本包**：它们都是「第三方给一个稳定
id」这个形状，宿主握完手直接调 `login_with_identity`，这边只是 `AuthProvider` 多
一个成员，没有任何 DDL 变化。

### 两条红线

**不按邮箱 / 手机号自动合并账号。** 匹配键只有 `(provider, external_id)`。第三方
返回的邮箱是用户自己填的 —— 要是能用它认领一个同邮箱的已有账号，攻击者只要在微信
侧把邮箱改成受害者的，扫一下码就直接登进了对方账号。要合并必须由**已登录**的用户
主动走 `link_identity`，那时候他已经证明了自己同时拥有两边。

**不许解绑最后一种登录方式。** `unlink_identity` 会先数一遍（密码算一种，每个外部
身份算一种），只剩一种时抛 `LastLoginMethod`。用户点「解绑微信」时不会想到这是他
唯一的入口，而解完的后果是一个谁都进不去的账号，只能靠运维去库里改。

## 邮箱 / 短信验证码

这条链路**整个在本包里** —— 和扫码相反。签发、哈希、原子消耗、试错限次、发送限频
每一条都是安全核心，让每个宿主自己写一遍必然有人写漏。宿主只提供一件事：把这段
文字发出去。

```python
# 1. 签发。明文只在这里出现这一次，库里存的是 bcrypt 哈希
code, _ = await accounts.issue_verification_code(session, AuthProvider.EMAIL, email)
await my_mailer.send(email, f"验证码：{code}，10 分钟内有效")  # 宿主的通道

# 2. 用户把码填回来 —— 校验 + 登录 + 没注册过就建号，一步到位
user, created = await accounts.login_with_code(session, AuthProvider.EMAIL, email, code)
```

默认 10 分钟有效、同一标识 60 秒内只能发一次、最多试错 5 次。短信比邮件贵，真上
短信的时候建议把间隔调大。

`issue_verification_code` 会**作废这个标识之前所有还没用的码**：同时有三个有效码
（用户连点了三次「重新发送」）等于把爆破成功率翻三倍，而且「我该输哪个」对用户
也是困惑。

### 试错计数为什么单独提交

`verify_code` 在校验结果出来**之前**先把 `attempts` 递增并提交。这是故意的 ——
失败时调用方（FastAPI 宿主的会话依赖）会 rollback，次数要是跟着回滚，这个上限就
完全不存在：爆破方每次失败都顺手帮自己把计数清零。安全计数器必须活过它所记录的
那次失败。

代价是这个方法在失败路径上会提交一次，所以请在请求的早期调用它，别在同一个会话里
攒了一堆待写的东西之后才调。

## 异常

全是 `RuntimeError` 的子类，**不是** HTTP 异常：

| 异常 | 什么时候抛 | 建议状态码 |
| --- | --- | --- |
| `BadCredentials` | 用户名不存在 / 密码不对 / 账号停用 / 没设过密码 | 401 |
| `UsernameTaken` | 用户名已被占用 | 409 |
| `InviteUnusable` | 邀请码不存在 / 已吊销 / 已过期 / 已用完 | 400 |
| `PermissionDenied` | 角色不满足要求 | 403 |
| `VerificationFailed` | 验证码不存在 / 不对 / 已过期 / 已用过 / 试错超限 | 400 |
| `VerificationThrottled` | 发送过于频繁 | 429 |
| `AccountDisabled` | 凭据对，但账号被停用 | 403 |
| `SignupDisabled` | 这个外部身份没绑过账号，且注册未开放 | 403 |
| `IdentityTaken` | 这个外部身份已绑在别的账号上 | 409 |
| `LastLoginMethod` | 不能解绑：这是最后一种登录方式 | 409 |

`BadCredentials`（四种）、`InviteUnusable`（四种）、`VerificationFailed`（五种）
各自**共用一条消息**，刻意不区分：分开报的话登录接口就是个用户名枚举器（拿字典
刷一遍，回「密码不对」的那些就是真实存在的账号），注册接口就是个「这个码存不存在」
的探测器。真正需要知道区别的是运维自己，而运维看得到数据库。

而 `AccountDisabled` / `SignupDisabled` / `IdentityTaken` **刻意说实话** ——
能走到它们的前提是对方已经证明了自己拥有那个外部身份，含糊其辞不多保护任何东西，
只会让他去反复重试一个永远不会成功的操作。

## FastAPI

`pip install "funauth[fastapi]"` 之后，路由和门禁都是现成的：

```python
from funauth.contrib.fastapi import CookieSessionStore, make_auth_router, make_user_deps

store = CookieSessionStore()
guard = make_user_deps(accounts=accounts, session_dep=SessionDep, store=store)

app.add_middleware(SessionMiddleware, secret_key=settings.secret_key)
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

`make_auth_router` 挂出五个端点，**全部公开** —— 否则没登录的人连登录接口都打不开：

| 端点 | 说明 |
|---|---|
| `GET /auth/config` | `{"registration_enabled": bool}`，前端据此决定要不要渲染注册入口 |
| `POST /auth/login` | 成功写会话并返回用户；失败 401 |
| `POST /auth/logout` | 204 |
| `GET /auth/me` | 当前登录者，**没登录返回 `null` 而不是 401** |
| `POST /auth/register` | 凭邀请码注册，201 / 400 / 409；`invite_model` 为 `None` 时不挂这条 |

### 验证码登录的路由

`make_code_login_router` 同时服务邮箱和短信 —— 两者在本包里是同一条链路，只有
`provider` 和发送通道不同。要两种都上就调两次：

```python
from funauth import AuthProvider
from funauth.contrib.fastapi import make_code_login_router

app.include_router(
    make_code_login_router(
        accounts=accounts,
        session_dep=SessionDep,
        store=store,
        provider=AuthProvider.EMAIL,
        sender=send_email,  # -> /auth/email/*
        registration_enabled_dep=RegistrationEnabledDep,
    )
)
app.include_router(
    make_code_login_router(
        accounts=accounts,
        session_dep=SessionDep,
        store=store,
        provider=AuthProvider.PHONE,
        sender=send_sms,  # -> /auth/phone/*
        min_interval_seconds=120,  # 短信更贵，隔久点
    )
)
```

`sender` 是宿主提供的 `async (target, code) -> None`。**别在里面记明文日志** ——
那等于把所有人的验证码写进日志系统。

| 端点 | 说明 |
|---|---|
| `POST /auth/{provider}/code` | 签发并发送，204；限频 429（带 `Retry-After`）；发送失败 502 |
| `POST /auth/{provider}/login` | 校验 + 登录 + 没注册过就建号，200 / 400 / 403 |

两条都**全部公开**。`/code` 对任何标识都照发，不管它注册过没有 —— 验证码登录本身
就兼注册，「没注册」不是一种失败。注册开关关着时也照发，只在 `/login` 那步回 403：
看起来绕，但另一种做法（没注册就不发）等于把「这个邮箱注册过没有」做成一个公开
查询接口，而在 `/login` 泄漏只泄漏给能收到这封邮件的人 —— 也就是那个邮箱的主人。

发送失败时会把刚签发的那条记录**删掉**再回 502：不删的话用户既没收到码、又要被
限频挡 60 秒，而这完全是服务端的故障。

### 整站门禁 + 后台管理员，两道门

典型需求是「整站要登录才能看，后台还要管理员」。这是两个依赖，不是一个，
`make_user_deps` 一次给出来，直接写在 handler 签名里：

```python
@router.get("/works")
async def list_works(session: SessionDep, _: guard.current_user): ...  # 登录即可


@router.get("/stats")
async def stats(session: SessionDep, _: guard.admin_user): ...  # 还要 ADMIN
```

匿名拿 401，登录了但不是管理员拿 **403**（不是 404 —— 路由表在前端代码里本来就是
公开的，装作「没有这个接口」除了让人困惑没有别的收益）。

门禁要落在后端。纯前端路由守卫挡不住直接 `curl` 接口 —— 静态文件服务器和反向
代理层通常没有鉴权，前端拦一道等于没拦。

### 会话里只存 user_id

默认的 `CookieSessionStore` 走 Starlette 的签名 cookie（宿主自己装
`SessionMiddleware`，secret_key / 有效期 / `https_only` 都是部署决定）。它**只存
user_id，不存角色** —— 角色每个请求重新查库，这样停用或降级一个账号之后他手上
那张还没过期的 cookie 立刻失效，而不是等到下次登录。

走 JWT 或 Redis 的宿主实现 `SessionStore` 协议即可，三个方法：

```python
class SessionStore(Protocol):
    def login(self, request: Request, user_id: str) -> None: ...
    def current(self, request: Request) -> str | None: ...
    def logout(self, request: Request) -> None: ...
```

会话里存的是**字符串**，而主键是 UUID，所以读回来要转一次。转不过去（上一套会话
方案留下的 cookie、换过 secret_key、你的 store 存了别的结构）按「登录已失效」处理
—— 清掉会话、门禁回 401、`/me` 回 `null`，**不会变成 500**。

主键不是 UUID 的宿主传 `parse_user_id` 换掉这一步，并且把 `user_out` 一起换掉
（`UserOut.id` 是 `uuid.UUID`，两处必须对得上）：

```python
guard = make_user_deps(accounts=accounts, session_dep=SessionDep, store=store, parse_user_id=int)
```

### funauth 不起服务

包里**没有** `FastAPI()` 实例、没有 uvicorn 入口，只导出一个装好的 `APIRouter`
跑在宿主进程里。有三件事必须共享进程才成立：

1. **事务**。凭码注册要让「扣名额」和「建账号」同生共死，现在它就是一个
   `session.commit()`。跨进程就得靠补偿逻辑或分布式事务。
2. **cookie 同域**。签名 cookie 必须同域才会带上。
3. **外键**。`user` 表长在宿主的 `Base` 上，宿主自己的表能正常 FK 引用 `user.id`。

代价是宿主必须是 **Python + FastAPI + SQLAlchemy async**。要给 Go / Node 服务共用
同一批账号才需要真起一个服务 —— 届时加个 `server.py` 把同一个 router 挂到一个新
`FastAPI()` 上，现有宿主一行不用改。另外同一个库上有多个宿主时，schema 变更仍然
走宿主自己的 alembic，**共库的宿主要一起升级**。

## 邀请码为什么是一条 UPDATE

`consume_invite` 把「还能不能用」整个塞进 WHERE，由数据库裁决：

```sql
UPDATE invite_code SET used_count = used_count + 1
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

## 往后再加登录方式

**再接一家第三方不用改本包。** 抖音、飞书、GitHub OAuth 都是「第三方给一个稳定
id」这个形状：宿主握完手调 `login_with_identity`，这边只是 `AuthProvider` 多一个
成员，没有 DDL 变化、没有新代码。

需要新 mixin 的是**形状**不同的方式，比如 WebAuthn / passkey（要存公钥、要走
challenge-response）。那时候照 `services/identity.py` 的样子写一个挂到 `Accounts`
上即可，`User` 表同样不用动 —— 多种登录方式共用一个账号，靠身份表关联，而不是给
`User` 不断加列。

## 从 0.2.x 升级

`User.password_hash` 现在是**可空**的（微信 / 验证码注册出来的账号没有密码），
已有库需要一条迁移：

```sql
ALTER TABLE "user" ALTER COLUMN password_hash DROP NOT NULL;
```

`authenticate` 对空哈希一律判失败，并且和「用户不存在」共用同一条消息和同一份
耗时，所以放开之后不会出现「空密码能登进去」。

要用新的登录方式才需要建 `identity` / `verification_code` 两张表；只用密码和邀请码
的话，除了上面那条 `ALTER` 不用动任何东西。

## 源码导览

每个模块的 docstring 里写的是**为什么这么设计**，比这份 README 更细。要改某块
之前先读那里 —— 很多写法是踩过坑才那样的，注释里记着是哪个坑。

| 文件 | 内容 | docstring 里回答了什么 |
|---|---|---|
| `models/mixins.py` | 四张表的 mixin | 为什么导出 mixin 而不是现成模型类；唯一约束和外键为什么留给宿主；时间列为什么是可选的 |
| `models/types.py` | `PkType`、`uuid7()`、`UTCDateTime` | 为什么自己实现 uuid7；SQLite 和 PostgreSQL 的时区行为差异怎么抹平 |
| `enums.py` | `UserRole`、`AuthProvider` | 为什么枚举列不建 CHECK 约束；角色为什么不做数值比较 |
| `errors.py` | `AuthError` 及子类 | 哪些失败必须共用一条消息，哪些该说实话，各自的理由 |
| `security.py` | bcrypt 两函数 | 为什么不用 passlib；为什么脏哈希返回 `False` 而不抛 |
| `services/base.py` | `AccountsBase` | 为什么是实例持有而不是模块级全局；事务边界那四档 |
| `services/password.py` | 密码登录、建号改密 | 为什么失败路径也要跑一次 bcrypt（时序侧信道） |
| `services/invite.py` | 邀请码 | 为什么消耗必须是一条条件 UPDATE 且不提交 |
| `services/identity.py` | 外部身份 | 为什么握手不在包内；为什么绝不按邮箱自动合并账号；并发怎么靠唯一约束兜住 |
| `services/verification.py` | 邮箱 / 短信验证码 | 为什么这条链路反而整个在包内；试错计数为什么单独提交；标识为什么要规整 |
| `contrib/fastapi.py` | 路由与门禁工厂 | 为什么不自带 `FastAPI()` 实例；注册开关为什么必须是个依赖而不是 bool |

测试也是文档 —— 每条测试的 docstring 写的是「它在防哪个具体的 bug」：

| 文件 | 钉住什么 |
|---|---|
| `test_accounts.py` | 密码登录、角色、邀请码全生命周期、凭码注册 |
| `test_transactions.py` | 事务那四档行为；本包逻辑不依赖宿主的时间列 |
| `test_timing.py` | 两条失败路径的哈希次数相同（测次数而不是墙上时钟，后者必然 flaky） |
| `test_identity.py` | 绑定/解绑、不自动合并账号、无密码账号不会把登录接口打成 500 |
| `test_verification.py` | 限频、限次、一次性、标识规整、试错计数活过 rollback |
| `test_fastapi.py` | 真起 app 打请求：两道门的状态码、cookie 隔离、自定义 store、脏会话 |
| `test_fastapi_code_login.py` | 验证码路由端到端：明文不入响应、发送失败回滚、爆破被拦 |
| `test_packaging.py` | `py.typed` 在位（没它下游拿不到类型标注） |

## 开发

```bash
# 首次：把源码装成 editable。装成拷贝的话跑测试测的是 site-packages 里的旧代码，
# 而那种情况下测试照样全绿 —— 你改的东西压根没被执行到。
uv sync

uv run --group dev pytest -q
uv run --group dev ruff format src tests
uv run --group dev ruff check --fix src tests
```

改动对外行为（公开 API、表结构、HTTP 行为、安全性质）时，同时更新
[CHANGELOG.md](CHANGELOG.md) 的「未发布」一节。纯内部重构不用记 —— 那些看 git log。

## 许可证

MIT，见 [LICENSE](LICENSE)。
