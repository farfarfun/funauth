# 变更记录

本文件记录 funauth 每个版本的对外变化。格式参考
[Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循
[语义化版本](https://semver.org/lang/zh-CN/)。

「对外变化」指的是**宿主项目能感知到的**东西：公开 API、表结构、HTTP 行为、
安全性质。纯内部重构和注释改动不记在这里 —— 那些看 git log。

## [未发布]

本次是一次较大的功能扩张（新增两种登录方式）加三个安全修复。`User` 表有一处
**破坏性变更**，见下面的「升级指引」。

### 新增

- **外部身份登录**（微信 / QQ 扫码等），`funauth.services.identity`：
  - `ExternalIdentityMixin` 表 mixin：`(provider, external_id) -> user_id`
  - `Accounts.login_with_identity()` —— 凭外部身份登录，没绑过就当场建号，
    返回 `(账号, 是否新建)`
  - `Accounts.link_identity()` / `unlink_identity()` / `list_identities()` /
    `count_login_methods()`
  - `AuthProvider` 枚举（`EMAIL` / `PHONE` / `WECHAT` / `QQ`）
  - `default_identity_username()` —— 给外部身份注册出来的账号生成本地用户名
  - 和第三方的握手**不在本包内**（需要 httpx、appid/secret、跟着平台文档变）。
    宿主握完手把 `external_id` 交进来即可。因此再接抖音 / 飞书 / GitHub OAuth
    不需要改本包，只是 `AuthProvider` 多一个成员。
- **邮箱 / 短信验证码登录**，`funauth.services.verification`：
  - `VerificationCodeMixin` 表 mixin
  - `Accounts.issue_verification_code()` —— 签发并返回明文（**只此一次**，库里
    存 bcrypt 哈希），自动作废该标识之前所有未使用的码
  - `Accounts.verify_code()` / `login_with_code()`
  - `generate_verification_code()` / `normalize_target()`
  - 默认 10 分钟有效、同标识 60 秒限发一次、最多试错 5 次
  - 这条链路整个在包内（签发、哈希、原子消耗、限次、限频都是安全核心），宿主
    只提供一个「把这段文字发出去」的异步回调
- `funauth.contrib.fastapi.make_code_login_router()` —— 验证码登录的现成路由
  （`POST /auth/{provider}/code` 和 `POST /auth/{provider}/login`）。邮箱和短信
  共用这一个工厂，调两次即可。
- 公开写方法新增 `commit` 关键字参数（`create_user`、`set_password`、
  `set_active`、`issue_invite`、`revoke_invite`、`register_with_invite`）。
  默认 `True` 保持原行为；传 `False` 只 flush，把提交留给调用方 —— 用于把账号
  操作和宿主自己的写入凑进同一个事务。
- `make_user_deps()` / `make_auth_router()` 新增 `parse_user_id` 参数（默认
  `uuid.UUID`），给主键不是 UUID 的宿主留出口。
- 新异常：`AccountDisabled`、`SignupDisabled`、`IdentityTaken`、
  `LastLoginMethod`、`VerificationFailed`、`VerificationThrottled`。
- `py.typed` 标记文件。按 PEP 561，没有它下游的 mypy / pyright 看不到本包的
  **任何**类型标注（全部退化成 `Any`）——此前标注写得很全但等于白写。
- `CHANGELOG.md`（本文件）。

### 变更（破坏性）

- **`UserMixin.password_hash` 改为可空**（`Mapped[str | None]`）。外部身份注册
  出来的账号没有密码，空值表示「该账号未开启密码登录」，不表示「密码是空的」。
  已有数据库需要一条迁移，见下面的「升级指引」。
- `PasswordMixin._insert()` 与 `create_user()` 的 `password` 参数接受 `None`，
  用于建立只能靠外部身份登录的账号。
- `verify_password()` 的 `password_hash` 参数类型放宽为 `str | None`，空值返回
  `False`。

### 修复

- **`authenticate()` 的时序侧信道。** 用户不存在 / 已停用时原来直接返回、不做
  bcrypt，于是虽然错误消息一致，响应时间差一个数量级（bcrypt 上百毫秒 vs 一次
  索引查询不到一毫秒）。拿字典刷一遍按耗时排序就能把真实账号筛出来，共用消息的
  努力被完全抵消。现在失败路径也对一个固定假哈希跑一次 bcrypt。
- **`verify_password()` 遇到脏数据会抛异常而不是返回 `False`。** 原来只 catch
  `ValueError`；`password_hash` 为 `None` 时 `None.encode()` 抛的是
  `AttributeError`，会变成 500。现在 `TypeError` / `AttributeError` 一并当作
  校验失败。
- **脏会话值会导致 500。** `make_user_deps` 和 `GET /auth/me` 原来直接
  `uuid.UUID(session_value)`，会话里存了非 UUID 的东西（换过会话方案、换过
  secret_key、宿主自定义 `SessionStore` 存了别的结构）时抛 `ValueError` →
  500。现在按「登录已失效」处理：清掉会话、门禁回 401、`/me` 回 `null`。
- **`consume_invite()` / `revoke_invite()` 隐式要求邀请码表有 `updated_at` 列。**
  两者原来在 `.values()` 里手写这个列，而它属于可选的 `TimestampMixin` ——
  宿主只继承 `InviteCodeMixin`、或自己的时间列叫别的名字时会在运行时报错。
  现在交给列自身的 `onupdate`，没有这个列也能正常运行（有则照常推进）。

### 文档

- `AccountsBase` 的 docstring 与 README 原来声称「什么时候提交由调用方决定」，
  而实际上 6 个写方法自己 `commit()`。现在三档行为（公开写方法默认提交 /
  `consume_invite` 从不提交 / 回滚始终归调用方）在两处都写准了。
- README 增补：外部身份、验证码、异常对照表（含建议状态码）、升级指引，以及
  「首次开发请先 `uv sync`」—— 否则跑的是 site-packages 里的旧副本，本地测试
  会在不知不觉中测错代码。

### 测试

从 49 条增至 147 条。新增文件：

| 文件 | 钉住什么 |
|---|---|
| `test_transactions.py` | 事务三档行为、不依赖宿主的时间列 |
| `test_timing.py` | 两条失败路径的哈希次数相同（不测墙上时钟） |
| `test_identity.py` | 身份绑定/解绑、不按邮箱自动合并、无密码账号 |
| `test_verification.py` | 限频、限次、一次性、标识规整、试错计数活过回滚 |
| `test_fastapi_code_login.py` | 验证码路由端到端（含明文不入响应、发送失败回滚） |
| `test_packaging.py` | `py.typed` 在位 |

### 升级指引

从 0.2.x 升级，已有数据库执行：

```sql
ALTER TABLE "user" ALTER COLUMN password_hash DROP NOT NULL;
```

`authenticate()` 对空哈希一律判失败，且与「用户不存在」共用同一条消息和同一份
耗时，所以放开约束不会产生「空密码能登录」。

只用密码和邀请码的话，除这条 `ALTER` 之外无需改动 —— 新增的 `identity` /
`verification_code` 两张表只在启用对应登录方式时才需要建。

---

## [0.2.1] - 2026-10-09

### 变更

- 版本号修订，无功能变化。

## [0.2.0] - 2026-10-09

### 新增

- `funauth[fastapi]` extra 与 `funauth.contrib.fastapi`：
  - `make_auth_router()` —— 五个现成端点（`/auth/config`、`/login`、`/logout`、
    `/me`、`/register`），全部公开（否则没登录的人连登录接口都打不开）。
    `invite_model` 为 `None` 时不挂 `/register`，OpenAPI 里也不会出现一个必然
    失败的端点。
  - `make_user_deps()` —— 整站门禁 `current_user` 与管理员 `admin_user` 两个
    依赖注解。匿名 401，已登录但角色不够 403。
  - `SessionStore` 协议与 `CookieSessionStore`（Starlette 签名 cookie）。会话里
    只存 `user_id`、角色每请求查库，所以停用或降级一个账号会让他手上的 cookie
    立刻失效。
  - `UserOut` / `LoginPayload` / `RegisterPayload` / `AuthConfigOut`。
- `fastapi` extra 的依赖下限刻意写低（`fastapi>=0.100`）：这个约束会传导给每个
  宿主，而本模块只用到 `APIRouter` / `Depends` / `HTTPException` / `Request`。

## [0.1.2] - 2026-10-09

### 新增

- `.gitignore`；从版本控制中移除误提交的构建产物（`__pycache__`）。
- README。

## [0.1.1] - 2026-10-09

首个发布版本。

### 新增

- 密码登录（bcrypt，不用 passlib），用户名不存在 / 密码不对 / 账号停用共用
  一条错误消息。
- 两级角色 `UserRole.ADMIN` / `GUEST`，判定用精确相等而非数值比较。
- 邀请码注册：限次、限期、可单独吊销。名额消耗是**一条条件 UPDATE**，把「还能
  不能用」整个塞进 WHERE 由数据库裁决，所以一张 `max_uses=1` 的码在并发下不会
  兑出两个账号。`register_with_invite` 的角色硬编码为 `GUEST`。
- 表结构以 mixin 形式提供（`UserMixin` / `InviteCodeMixin` / `TimestampMixin`），
  具体表由宿主声明在自己的 `Base` 上 —— 一套 `MetaData`、一条迁移链、外键照常写。
- 可移植列类型：`PkType`（UUID 主键）、自实现的 `uuid7()`（标准库 3.14 才有）、
  `UTCDateTime`（抹平 SQLite 与 PostgreSQL 在时区上的行为差异）。
- 异常体系 `AuthError` 及其子类，全部是 `RuntimeError` 子类而非 HTTP 异常 ——
  核心层不依赖任何 web 框架。

[未发布]: https://github.com/farfarfun/funauth/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/farfarfun/funauth/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/farfarfun/funauth/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/farfarfun/funauth/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/farfarfun/funauth/releases/tag/v0.1.1
