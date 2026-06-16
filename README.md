# OAuth2 / OIDC 授权服务器

完整的 OAuth2 与 OpenID Connect (OIDC) 授权服务器实现，支持授权码、客户端凭证、刷新令牌等流程。

## 快速开始

```bash
npm install
npm start
```

服务器默认运行在 `http://localhost:3000`

## 模块架构

```
├── config.js          # 全局配置（密钥、令牌过期时间、作用域等）
├── clients.js         # 客户端管理（注册、验证、作用域校验）
├── auth.js            # 用户认证（注册、登录、会话管理）
├── tokenService.js    # 令牌服务（授权码、JWT签发/校验、刷新令牌轮换、撤销）
├── authorization.js   # 授权端点（/authorize - 授权请求与用户授权）
├── token.js           # 令牌端点（/token、/revoke、/introspect）
├── oidc.js            # OIDC 模块（ID Token、UserInfo、Discovery）
├── server.js          # Express 服务器入口
└── views/
    ├── login.ejs      # 登录页面
    └── authorize.ejs  # 授权确认页面
```

## 测试账号

| 用户名 | 密码 | 姓名 |
|--------|------|------|
| alice | password123 | Alice Wang |
| bob | password456 | Bob Li |

## 端点列表

| 端点 | 方法 | 说明 |
|------|------|------|
| `/authorize` | GET/POST | 授权端点 |
| `/token` | POST | 令牌端点（换取 access_token） |
| `/revoke` | POST | 令牌撤销端点 |
| `/introspect` | POST | 令牌内省端点 |
| `/userinfo` | GET | OIDC 用户信息端点 |
| `/.well-known/openid-configuration` | GET | OIDC 发现文档 |
| `/.well-known/jwks.json` | GET | JWKS 公钥集 |
| `/login` | GET/POST | 用户登录 |
| `/logout` | POST | 用户登出 |

---

## 一、授权码流程（Authorization Code Flow）

授权码流程是 OAuth2 中最安全、最常用的流程，适用于有后端服务器的 Web 应用（Confidential Clients）。

### 步骤 1：授权请求（Authorization Request）

客户端将用户浏览器重定向到授权服务器的 `/authorize` 端点：

```
GET /authorize?
    response_type=code
    &client_id=<客户端ID>
    &redirect_uri=http://localhost:3001/callback
    &scope=openid profile email read
    &state=<随机防CSRF字符串>
    &nonce=<OIDC防重放随机值>
    &code_challenge=<PKCE挑战值>
    &code_challenge_method=S256
```

**参数说明：**
- `response_type=code`：表示使用授权码流程
- `client_id`：客户端标识
- `redirect_uri`：用户授权后回调的 URI，必须与注册时一致
- `scope`：请求的权限范围，空格分隔
- `state`：客户端生成的随机值，用于防止 CSRF 攻击
- `nonce`：OIDC 特有，用于防止 ID Token 重放攻击
- `code_challenge` / `code_challenge_method`：PKCE 参数

### 步骤 2：用户认证与授权

授权服务器：
1. 检查用户是否已登录（通过 session cookie），未登录则跳转登录页
2. 验证客户端 ID、重定向 URI、响应类型等参数合法性
3. 展示授权确认页面，列出客户端请求的所有权限范围
4. 用户点击「授权」或「拒绝」

代码位置：[authorization.js](file:///d:/trae-bz/TraeProjects/35/authorization.js#L36-L114) 的 GET `/authorize`

### 步骤 3：发放授权码（Authorization Code）

用户同意授权后，授权服务器生成一次性短效授权码，并重定向回客户端：

```
HTTP 302 Redirect: http://localhost:3001/callback?
    code=<授权码>
    &state=<原样返回的state值>
```

**授权码的关键特性：**
- **一次性（One-Time Use）**：授权码只能使用一次，使用后立即标记为 `used=true`，第二次使用会报错 `invalid_grant`
- **短效（Short-Lived）**：默认有效期仅 600 秒（10 分钟），过期自动清理
- **绑定客户端**：授权码记录了 `clientId`，兑换时必须由同一个客户端使用
- **绑定回调 URI**：授权码记录了 `redirectUri`，兑换时必须使用完全相同的 URI
- **绑定 PKCE**：如果请求时携带了 `code_challenge`，兑换时必须提供对应的 `code_verifier`

代码位置：[tokenService.js](file:///d:/trae-bz/TraeProjects/35/tokenService.js#L11-L88) 的 `generateAuthorizationCode` 和 `validateAuthorizationCode`

### 步骤 4：用授权码换取令牌（Token Exchange）

客户端后端服务器向 `/token` 端点发送 POST 请求：

```
POST /token
Content-Type: application/x-www-form-urlencoded
Authorization: Basic <Base64(clientId:clientSecret)>

grant_type=authorization_code
&code=<步骤3获得的授权码>
&redirect_uri=http://localhost:3001/callback
&code_verifier=<PKCE验证值>
```

授权服务器验证通过后返回：

```json
{
  "access_token": "<JWT访问令牌>",
  "token_type": "Bearer",
  "expires_in": 900,
  "scope": "openid profile email read",
  "refresh_token": "<刷新令牌>",
  "id_token": "<OIDC身份令牌>"
}
```

代码位置：[token.js](file:///d:/trae-bz/TraeProjects/35/token.js#L66-L128) 的 `handleAuthorizationCode`

### 授权码为何需要「一次性、短效、绑定客户端与回调」？

| 特性 | 原因 | 攻击防护 |
|------|------|----------|
| **一次性** | 授权码通过浏览器 URL 传递，可能被日志、浏览器历史、中间人记录。一次性确保即使泄露也无法重复使用 | 防止授权码泄露后被滥用 |
| **短效（10分钟）** | 缩短授权码的可攻击时间窗口，即使被截获也很快失效 | 降低泄露授权码的风险窗口 |
| **绑定客户端** | 授权码只能由发放时的 client_id 兑换，即使其他客户端截获授权码也无法使用 | 防止跨客户端滥用授权码 |
| **绑定回调 URI** | 必须使用完全相同的 redirect_uri 兑换，防止攻击者将授权码发送到恶意回调地址 | 防止开放重定向攻击和授权码劫持 |

---

## 二、JWT 访问令牌的签名与校验

### JWT 结构

JSON Web Token 由三部分组成，用 `.` 分隔：

```
<Base64Url(Header)>.<Base64Url(Payload)>.<Base64Url(Signature)
```

**Header（头部）：**
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

**Payload（载荷）** - 本项目包含的标准声明：
```json
{
  "iss": "http://localhost:3000",
  "sub": "<用户ID>",
  "aud": "<客户端ID>",
  "iat": 1718600000,
  "exp": 1718600900,
  "jti": "<唯一令牌ID>",
  "scope": "openid profile email read",
  "client_id": "<客户端ID>",
  "user_id": "<用户ID>"
}
```

| 声明 | 说明 |
|------|------|
| `iss` (Issuer) | 令牌签发者，必须等于授权服务器地址 |
| `sub` (Subject) | 令牌主体（用户ID或客户端ID） |
| `aud` (Audience) | 令牌受众（客户端ID） |
| `iat` (Issued At) | 签发时间戳 |
| `exp` (Expiration) | 过期时间戳 |
| `jti` (JWT ID) | 令牌唯一标识，用于撤销 |
| `scope` | 权限范围 |
| `client_id` | 申请令牌的客户端 |

### 签名过程（HS256 - HMAC-SHA256）

```
Signature = HMAC-SHA256(
    base64UrlEncode(header) + "." + base64UrlEncode(payload),
    服务器密钥
)
```

代码位置：[tokenService.js](file:///d:/trae-bz/TraeProjects/35/tokenService.js#L113-L133) 的 `generateAccessToken`

### 校验过程

资源服务器收到 JWT 后需依次校验：

1. **格式校验**：三段式结构，Base64Url 可解码
2. **签名校验**：使用相同密钥重新计算签名，与令牌中的签名对比
3. **标准声明校验**：
   - `exp` > 当前时间（令牌未过期）
   - `iss` 等于预期的授权服务器地址
   - `aud` 包含本服务标识
4. **业务校验**：`scope` 是否包含所需权限

代码位置：[tokenService.js](file:///d:/trae-bz/TraeProjects/35/tokenService.js#L135-L156) 的 `verifyAccessToken`

---

## 三、刷新令牌轮换（Refresh Token Rotation）与盗用检测

### 刷新令牌 vs 访问令牌

| 特性 | Access Token | Refresh Token |
|------|--------------|---------------|
| 有效期 | 15 分钟（短效） | 30 天（长效） |
| 用途 | 访问受保护资源 | 换取新的 Access Token |
| 存储位置 | 前端内存、请求头 | HttpOnly Cookie、安全存储 |
| 泄露风险 | 高（频繁使用） | 低（仅在刷新时使用） |

### 刷新令牌轮换机制

每次使用 refresh_token 换取新 access_token 时，服务器**废弃旧 refresh_token**并**发放新 refresh_token**：

```
时间线：
RT1 (refresh_token_1) → 使用后立即作废 → 发放 RT2
RT2 → 使用后立即作废 → 发放 RT3
RT3 → ...
```

### 盗用检测原理

假设攻击者窃取了用户的 RT3：

1. **合法用户**先使用 RT3 → 服务器标记 RT3 已使用，发放 RT4
2. **攻击者**后使用 RT3 → 服务器检测到 RT3 已使用（`rotated=true`）
3. **安全响应**：立即吊销该客户端下该用户的**整个刷新令牌链**（RT1、RT2、RT3、RT4 全部作废）
4. 用户必须重新登录授权，攻击者的所有令牌全部失效

代码位置：
- 轮换逻辑：[tokenService.js](file:///d:/trae-bz/TraeProjects/35/tokenService.js#L203-L221) `rotateRefreshToken`
- 盗用检测：[tokenService.js](file:///d:/trae-bz/TraeProjects/35/tokenService.js#L179-L201) `validateRefreshToken` 第 195-198 行
- 链条吊销：[tokenService.js](file:///d:/trae-bz/TraeProjects/35/tokenService.js#L223-L249) `revokeRefreshTokenChain`

### 刷新令牌流程

```
POST /token
Content-Type: application/x-www-form-urlencoded
Authorization: Basic <Base64(clientId:clientSecret)>

grant_type=refresh_token
&refresh_token=<当前刷新令牌>
&scope=read profile  // 可选：只能缩小，不能扩大权限
```

响应返回新的 access_token 和新的 refresh_token。

代码位置：[token.js](file:///d:/trae-bz/TraeProjects/35/token.js#L151-L217) 的 `handleRefreshToken`

---

## 四、作用域（Scope）限制权限

### 作用域定义

在 [config.js](file:///d:/trae-bz/TraeProjects/35/config.js#L29-L36) 中定义了所有可用作用域：

| Scope | 说明 |
|-------|------|
| `openid` | OIDC 身份认证范围，必须存在才能获取 ID Token |
| `profile` | 用户基本资料（姓名、昵称、地区等） |
| `email` | 用户邮箱地址 |
| `read` | 资源读取权限 |
| `write` | 资源写入权限 |
| `admin` | 管理员权限 |

### 三层权限控制

1. **客户端注册时的作用域限制**：每个客户端预先注册允许请求的 scope
   - 例：Test Web App 允许 `openid profile email read write`
   - 例：Test Public App 只允许 `openid profile email read`

2. **用户授权时的作用域限制**：用户在授权页面看到并同意具体 scope

3. **令牌校验时的作用域限制**：资源服务器检查令牌 scope

代码位置：
- 客户端 scope 校验：[clients.js](file:///d:/trae-bz/TraeProjects/35/clients.js#L101-L110) `validateScope`
- 访问权限校验：[tokenService.js](file:///d:/trae-bz/TraeProjects/35/tokenService.js#L309-L319) `validateScopeAccess`

### 权限校验示例

```javascript
const result = tokenService.validateScopeAccess(decodedToken, ['read', 'write']);
if (!result.authorized) {
  // 缺少 result.missingScopes 中的权限
  return res.status(403).json({ error: 'insufficient_scope' });
}
```

---

## 五、OIDC 身份令牌（ID Token）与用户信息端点

### OIDC 是什么？

OpenID Connect (OIDC) 是构建在 OAuth2 之上的**身份认证层**。OAuth2 只解决「授权」（给令牌访问资源），OIDC 解决「认证」（知道用户是谁）。

### ID Token 结构

ID Token 是一个 JWT，包含用户身份声明（Claims）：

```json
{
  "iss": "http://localhost:3000",
  "sub": "<用户唯一ID>",
  "aud": "<客户端ID>",
  "exp": 1718603600,
  "iat": 1718600000,
  "auth_time": 1718600000,
  "jti": "<唯一ID>",
  "nonce": "<授权请求时的nonce>",
  "at_hash": "<access_token的哈希值>",
  "name": "Alice Wang",
  "given_name": "Alice",
  "family_name": "Wang",
  "nickname": "Ali",
  "preferred_username": "alice",
  "locale": "zh-CN",
  "zoneinfo": "Asia/Shanghai",
  "updated_at": "2024-06-17T00:00:00.000Z",
  "email": "alice@example.com",
  "email_verified": true
}
```

### 标准身份声明（Standard Claims）

| Claim | 说明 | 对应 Scope |
|-------|------|------------|
| `sub` | 用户唯一标识（必须） | - |
| `name` | 全名 | profile |
| `given_name` | 名 | profile |
| `family_name` | 姓 | profile |
| `nickname` | 昵称 | profile |
| `preferred_username` | 首选用户名 | profile |
| `locale` | 语言地区 | profile |
| `zoneinfo` | 时区 | profile |
| `updated_at` | 资料更新时间 | profile |
| `email` | 邮箱 | email |
| `email_verified` | 邮箱是否验证 | email |
| `nonce` | 防重放随机值 | openid |
| `at_hash` | Access Token 哈希 | openid |
| `auth_time` | 认证时间 | openid |

代码位置：
- ID Token 生成：[oidc.js](file:///d:/trae-bz/TraeProjects/35/oidc.js#L11-L39) `generateIdToken`
- 用户声明提取：[auth.js](file:///d:/trae-bz/TraeProjects/35/auth.js#L111-L128) `getUserClaims`

### UserInfo 端点

客户端使用 Access Token 调用 `/userinfo` 端点获取用户信息：

```
GET /userinfo
Authorization: Bearer <access_token>
```

响应：

```json
{
  "sub": "<用户ID>",
  "name": "Alice Wang",
  "given_name": "Alice",
  "family_name": "Wang",
  "nickname": "Ali",
  "preferred_username": "alice",
  "locale": "zh-CN",
  "zoneinfo": "Asia/Shanghai",
  "updated_at": "2024-06-17T00:00:00.000Z",
  "email": "alice@example.com",
  "email_verified": true
}
```

**返回声明的控制**：根据 Access Token 中的 `scope` 动态返回。例如 scope 中没有 `email`，则不会返回 email 相关字段。

代码位置：[oidc.js](file:///d:/trae-bz/TraeProjects/35/oidc.js#L95-L113) 的 GET `/userinfo`

### at_hash 和 c_hash 的作用

- **`at_hash`**：Access Token 的 SHA-256 哈希左半部分的 Base64Url 编码。客户端用它验证收到的 access_token 与 id_token 是否成对发放，防止令牌替换攻击。
- **`c_hash`**：授权码 code 的 SHA-256 哈希左半部分，作用类似，验证 code 与 id_token 成对。

---

## 六、PKCE 防止授权码拦截

### PKCE 是什么？

PKCE (Proof Key for Code Exchange，发音 "pixy") 是授权码流程的扩展安全机制，专为公共客户端（Public Client，如移动 App、SPA 单页应用）设计，防止授权码在传递过程中被拦截。

### 为什么需要 PKCE？

传统授权码流程依赖客户端密钥（client_secret），但公共客户端无法安全存储密钥（前端代码、移动端反编译可获取）。PKCE 用动态生成的临时密钥替代固定密钥。

### PKCE 流程

```
┌──────────┐                                  ┌────────────────┐
│ 客户端    │                                  │ 授权服务器      │
└────┬─────┘                                  └───────┬────────┘
     │ 1. 生成 code_verifier (随机字符串)              │
     │    code_challenge = BASE64URL(SHA256(verifier)) │
     │───────────────────────────────────────────────→│
     │    /authorize?response_type=code               │
     │    &code_challenge=<挑战值>                     │
     │    &code_challenge_method=S256                 │
     │                                                 │
     │←───────────────────────────────────────────────│
     │ 2. 返回授权码 code                              │
     │                                                 │
     │───────────────────────────────────────────────→│
     │ 3. POST /token                                 │
     │    grant_type=authorization_code               │
     │    code=<授权码>                                │
     │    code_verifier=<原始验证值>                   │
     │                                                 │
     │    服务端验证:                                  │
     │    SHA256(verifier) == 存储的 challenge?       │
     │←───────────────────────────────────────────────│
     │ 4. 返回令牌                                     │
```

### 为什么 PKCE 能防拦截？

1. 即使攻击者在步骤 2 截获了授权码 `code`
2. 攻击者不知道 `code_verifier`（它从未通过网络传输，只在客户端本地生成）
3. 攻击者无法计算出正确的 `code_verifier` 来完成步骤 3
4. 没有 `code_verifier`，授权码无法兑换为令牌

### code_verifier 和 code_challenge 的关系

```javascript
// 1. 客户端生成 code_verifier（43-128 字符的随机字符串）
const code_verifier = generateCodeVerifier();

// 2. 计算 code_challenge
const code_challenge = base64url(sha256(code_verifier));

// 3. 授权服务器验证
const computed = base64url(sha256(received_verifier));
if (computed !== stored_challenge) {
  throw new Error('PKCE verification failed');
}
```

代码位置：
- 挑战值计算：[tokenService.js](file:///d:/trae-bz/TraeProjects/35/tokenService.js#L90-L111) `computeCodeChallenge` 和 `generateCodeVerifier`
- PKCE 验证：[tokenService.js](file:///d:/trae-bz/TraeProjects/35/tokenService.js#L69-L78) 在 `validateAuthorizationCode` 中

支持两种转换方法：
- **S256**（推荐）：`code_challenge = BASE64URL(SHA256(code_verifier))`
- **plain**：`code_challenge = code_verifier`（仅兼容旧客户端，不推荐）

---

## 七、无状态令牌的撤销处理

### 问题：JWT 是无状态的

JWT 的优势是**无状态**：签名验证即可判断有效性，无需查询数据库。但这也带来了问题：一旦签发，在过期前无法自然失效。

### 撤销方案

本项目采用**混合方案**，兼顾性能与安全：

#### 1. Access Token：短期 + 撤销黑名单

- **默认有效期 15 分钟**：即使无法撤销，风险窗口也很短
- **撤销黑名单（Revocation List）**：主动撤销的令牌加入内存 Set
- **校验时检查黑名单**：`verifyAccessToken` 先检查是否在 revokedTokens 中

```javascript
// 撤销令牌
POST /revoke
token=<access_token>
token_type_hint=access

// 校验时
if (revokedTokens.has(token)) {
  return { valid: false, error: 'Token has been revoked' };
}
```

#### 2. Refresh Token：状态存储 + 链条吊销

- Refresh Token 本身是**有状态**的（存储在服务器 Map 中）
- 可以随时删除或标记为已使用
- 支持**链条吊销**：检测到盗用时，吊销整个轮换链

#### 3. 客户端登出流程

```
POST /logout (前端)
  → 删除 session cookie
  → 可选：调用 /revoke 撤销当前 access_token 和 refresh_token
```

#### 4. 其他撤销策略（生产环境补充）

| 策略 | 说明 |
|------|------|
| **缩短 Access Token 有效期** | 5-15 分钟，降低撤销需求 |
| **网关层缓存黑名单** | Redis 存储，配合 TTL 自动清理过期令牌 |
| **jti 黑名单** | 存储已撤销令牌的 jti，而非完整 token 字符串，节省空间 |
| **密钥轮换** | 定期更换签名密钥，所有旧令牌自然失效 |
| **用户强制登出** | 将用户加入「强制重新认证」列表，下次令牌校验时触发 |

代码位置：
- 撤销端点：[token.js](file:///d:/trae-bz/TraeProjects/35/token.js#L219-L238) POST `/revoke`
- 撤销逻辑：[tokenService.js](file:///d:/trae-bz/TraeProjects/35/tokenService.js#L251-L264) `revokeToken`

---

## 八、客户端凭证流程（Client Credentials Flow）

适用于**无用户参与**的服务间通信（如后端 API 调用另一个后端 API）。

```
POST /token
Content-Type: application/x-www-form-urlencoded
Authorization: Basic <Base64(clientId:clientSecret)>

grant_type=client_credentials
&scope=read write
```

响应：

```json
{
  "access_token": "<JWT>",
  "token_type": "Bearer",
  "expires_in": 900,
  "scope": "read write"
}
```

特点：
- 不需要用户授权，使用客户端自身凭证
- Access Token 的 `sub` 为客户端 ID，没有 user_id
- 不发放 Refresh Token（客户端可随时用凭证重新获取）

代码位置：[token.js](file:///d:/trae-bz/TraeProjects/35/token.js#L130-L149) `handleClientCredentials`

---

## 九、令牌内省（Token Introspection）

资源服务器可以调用 `/introspect` 端点查询令牌状态：

```
POST /introspect
Authorization: Basic <Base64(clientId:clientSecret)>

token=<要查询的令牌>
token_type_hint=access_token  // 可选
```

响应：

```json
{
  "active": true,
  "scope": "openid profile read",
  "client_id": "<客户端ID>",
  "sub": "<用户ID>",
  "aud": "<受众>",
  "iss": "http://localhost:3000",
  "exp": 1718600900,
  "iat": 1718600000,
  "jti": "<令牌ID>",
  "token_type": "access_token"
}
```

若令牌无效或已撤销：`{"active": false}`

代码位置：[token.js](file:///d:/trae-bz/TraeProjects/35/token.js#L240-L259) POST `/introspect`

---

## 十、OIDC 发现端点

客户端自动发现授权服务器配置：

```
GET /.well-known/openid-configuration
```

返回标准 OIDC Discovery 文档，包含所有端点 URL、支持的 scope、grant_type、签名算法等信息。

代码位置：[oidc.js](file:///d:/trae-bz/TraeProjects/35/oidc.js#L115-L176)

---

## 安全设计总结

| 安全机制 | 实现位置 | 防护目标 |
|----------|----------|----------|
| 授权码一次性+短效 | tokenService.js `validateAuthorizationCode` | 防止授权码泄露重用 |
| 授权码绑定客户端+回调 | 同上 | 防止授权码劫持、开放重定向 |
| PKCE S256 | tokenService.js `computeCodeChallenge` | 防止公共客户端授权码拦截 |
| Refresh Token Rotation | tokenService.js `rotateRefreshToken` | 检测刷新令牌盗用 |
| Refresh Token Chain Revocation | tokenService.js `revokeRefreshTokenChain` | 盗用后整条链作废 |
| JWT HS256 签名 | tokenService.js `generateAccessToken` | 防篡改、防伪造 |
| 作用域三层控制 | clients.js、authorization.js | 最小权限原则 |
| state 参数（客户端） | /authorize 返回 | CSRF 防护 |
| nonce 参数 | ID Token | 重放攻击防护 |
| HttpOnly Cookie | auth.js `createSession` | XSS 防护会话 |
| Access Token 黑名单撤销 | tokenService.js `revokeToken` | 无状态令牌主动失效 |
| 密码 PBKDF2 哈希 | auth.js `hashPassword` | 密码存储安全 |
