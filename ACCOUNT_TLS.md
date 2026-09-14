# 账号 TLS 传输配置

HTTP reverse/forward 的目标连接池按 node、platform、account 和 profile 隔离。
有账号但没有显式 profile 的兼容请求，也会派生稳定的账号 TLS 配置。无账号请求保留原有行为。
HTTP CONNECT 与 SOCKS 是原始隧道，目标 TLS 由客户端生成，不做 MITM。

## 显式协议

受信任且已通过 proxy token 鉴权的 reverse 请求可使用：

```text
/<proxy-token>/<platform>/https+tls-v1/<target-host>/<path>
X-Resin-Account: <stable-account-or-gateway-generation>
X-Resin-TLS-Profile: v1:<index>:<sha256>
```

`index` 范围为 0 到 103,679，摘要必须为 64 位小写十六进制。缺失、非法或开放代理上的
显式配置会被拒绝。`https+tls-v1`/`http+tls-v1` 恢复为普通目标 scheme；不支持该协议的
旧 Resin 在解析路径时就拒绝，避免向目标站点发送未隔离的请求。普通路径仍可供兼容客户端使用。

显式 profile 通过响应 `X-Resin-TLS-Profile` 回执，目标的同名头会被剥离，不能伪造回执。
该回执表示账号 transport policy 已被选择；`http+tls-v1` 没有 TLS 握手，但仍隔离连接池。
请求控制头在离开 Resin 前删除，不发送给最终站点。
上游响应的 `X-Resin-Error` 同样剥离，只有 Resin 自己生成的错误可以触发内部恢复策略。

## TLS 与资源边界

uTLS 根据 profile 排列六个 TLS 1.2 ECDHE AEAD 套件、三个 TLS 1.3 套件与四条曲线，
与 MetAPI/AnyRouter helper 的 v1 参数协议一致。证书验证和 TLS 1.2 最低版本保留；
没有握手失败后回退默认 TLS 的路径。目标 HTTP 使用 HTTP/1.1，ALPN 同样只声明 HTTP/1.1，
避免 Go net/http 将自定义 uTLS 连接误用为 HTTP/2。

账号路径禁用 session tickets，不跨账号共享 TLS session。LRU 缓存最多 1,024 个 transport，
淘汰及节点撤销只关闭空闲连接，不中断在途请求。profile 组合空间有限，profile 相同也不会
使不同账号共享 transport；这不是所有 JA3/JA4 唯一或物理设备不可关联的保证。

## 验证

`internal/proxy/account_tls_test.go` 覆盖真实 ClientHello 捕获、TLS 1.2/1.3 可信握手、
不可信证书拒绝、账号连接分离与复用、LRU、控制头剥离和版本化入口校验。
`go test -race ./internal/proxy` 为核心验证；完整检查需先按仓库流程构建 `webui/dist`，
再执行 `go test -race ./...` 与 `go vet ./...`。测试不访问生产账号或真实上游。
