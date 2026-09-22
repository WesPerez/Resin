# Resin Egress Guard

`resin-egress-guard` 是所有 Resin 消费方共用的常驻故障守卫，不为每个下游创建 timer。

它消费以下被动证据：

- Resin 官方 `request-logs` 中 `net_ok=false` 的传输故障；
- 下游共享 HTTP 客户端发送到 `/v1/failures` 的标准化传输/出口信誉反馈；
- 迁移期内已有 Sub2API 结构化日志中的明确 OAuth 传输失败。
- Sub2API 流式响应缺少终止事件的精确信号。守卫从正式日志增量读取，核对账号当前
  Proxy（含 shadow 母账号归一）后，原子轮换 Resin lease 并关闭旧 lease 的连接。

守卫对普通传输证据执行精确的 Resin lease `GET` 和 `DELETE`；对 Sub2API 缺终止事件
执行带 `node_hash + created_at_ns` CAS 的 `POST .../rotate`。请求日志事件还会核对当前
`lease.node_hash == event.node_hash`，防止旧事件删除已经换新的 lease。它不会修改
Sub2API `proxy_id`，不会调用 `/test`，也不会重放失败的业务请求。

需要先积累证据时，可用 `serve --observe-only` 运行观测模式。该模式仍读取
Resin request-logs、账号、`node_hash` 和 `egress_ip` 并记录事件，但不会删除或
轮换任何 lease；恢复写模式前应重新核对证据窗口和影响范围。

## 轮换策略

- 明确拨号、SOCKS、TLS 和连接超时：一次事件立即轮换；
- tunnel copy EOF/reset 等歧义错误：60 秒内两次才轮换；
- `openai.forward_failed` 且 `stream=true`、错误精确为
  `stream usage incomplete: missing terminal event`：一次即轮换；账号冷却和平台风暴保护继续生效；
- 上游 `502/503/504/524`：不能单独证明 Resin 节点故障，不触发租约删除、换节点或关闭连接。
  524 在业务层按上游超时处理。升级前持久队列中的旧 524 事件也会被丢弃，不会补执行。
  即使反馈将 524 标记为 `transport_timeout`，最终处理入口仍忽略它；独立的拨号/TLS
  传输故障继续按原策略处理。启动日志中的 `sub2_upstream_rotation_statuses` 固定为空。
- 同账号最短 30 秒，15 分钟最多三次，之后冷却 60 分钟；
- 同平台 60 秒出现 20 个不同账号轮换后暂停 5 分钟，避免 bridge 整体重启时形成 IP 风暴；
- Resin 没有替代节点时，该 request ID 记为终态，新的 request ID 仍可再次尝试；
- Resin 或 Sub2API Admin API 短暂失败时，事件在持久队列中指数退避重试；默认最多 8 次、
  最长 5 分钟，之后写入有界审计死信并继续处理后续事件。队列最多保留 2048 条；
- `401`、普通 `403`、`429`、`500` 和客户端取消不会触发。

`feedback.listen_addresses` 可同时绑定多个明确的私网/回环地址，例如 Docker
默认 bridge 的 `172.17.0.1` 与 MetAPI 网络的 `172.20.0.1`。不要绑定公网地址或
`0.0.0.0`。反馈还必须携带 `allowed_sources` 中的明确 `source`，生产默认只允许
`metapi` 与 `sub2api`。

Cloudflare 挑战必须由能看到明文 HTTP 响应的下游共享网络层识别。TLS/SOCKS
隧道中的状态码对 Resin 不可见，这是协议边界，不是增加 Resin 轮询可以解决的问题。

## 重启与恢复

实时尾读将文件身份、读取位置和位置前的摘要与待处理事件一起原子保存；半行只保存其
起始位置，重启后重新读取。支持保留旧文件的 rename 轮转和 copytruncate 检测；若旧文件
已被删除，无法补回其中尚未读取的内容。首次启动没有断点时从文件末尾开始，不重放历史日志。
待处理队列只保存匹配事件所需的账号、请求标识、时间与错误类型，不保存原始业务日志。

轮换前持久保存原租约的 CAS 参数。即使 POST 已成功而响应或后续核验失败，重试也只携带
原版本，不会再次轮换新租约。同账号操作串行；网络等待期间释放全局状态锁，旧请求日志
扫描独立运行，空闲尾读不反复写盘。默认 0.25 秒是轮询间隔，实际反应时间还取决于日志
落盘、Admin API、Resin API 和待处理事件，不能保证客户端每次即时重试前都已换好出口。

## 部署

1. 对三个 Resin 的 `state.db`、`cache.db` 做 SQLite 在线备份并完成 `integrity_check`。
2. 仅 PATCH `{"request_log_enabled":true}`；保持 payload detail 关闭。
3. 安装私有配置 `/etc/server-scheduled-tasks/resin-egress-guard.json` 和
   `/etc/resin-egress-guard/feedback.token`，并通过 systemd `LoadCredential` 注入 Sub2API
   Admin API key。该 key 不写入 Git、配置或 state；轮换时原子替换私有凭据文件并重启服务，
   `admin.probe_account_id` 应设置为一个长期存在的账号；随后运行
   `validate --require-request-logs`，确认 Admin key 可读该账号且 Resin 平台身份可用。
4. 若反馈发送方位于 Docker bridge，只允许该 bridge 的源网段访问守卫绑定 IP 和
   feedback 端口；不要向公网开放。启用后必须从发送方容器内请求 `/healthz` 验证，
   不能只在宿主机验证。
5. 先运行 `validate --require-request-logs` 和 `scan`，再以 `serve --observe-only`
   启用 service；只有完成账号/IP/租约证据核对并明确授权后，才切换到
   `--confirm-production-write`。
6. 中央服务稳定后停用并卸载 `sub2api-egress-recovery.timer`；旧实现只保留在
   Git 历史中，不在生产服务器常驻。

生产使用已审查提交的固定目录时，将 `tasks/resin-egress-guard/` 导出至
`/opt/resin-egress-guard/releases/<commit>/`。通过 systemd drop-in 同时设置
`WorkingDirectory`、`Environment=TASK_DIR=<release>` 和清空后重设的 `ExecStart`，
并将 `/opt/resin-egress-guard` 加入 `ReadOnlyPaths`。只改变发布路径，不改变
`--confirm-production-write`、私有配置、凭据和 state 路径。避免工作区的未发布改动
在服务下次重启时自动进入生产。

升级前备份有效 unit/drop-in 与 state，检查目标发布目录和 `systemd-analyze verify`。
首次从无断点版本迁移时，在停止旧进程前记录日志末尾；停止后持有同一进程锁，将该断点
写入最新 state，保留原 pending、冷却和去重记录，再启动新版。已有断点时沿用原值。
启动后核对实际进程路径、`guard_started`、两端 `/healthz`、断点推进及队列状态。
发布记录见 [2026-09-12 验证记录](deployment-20260912.md)。

需要回滚到旧实现时，先停止本 service，再从对应审计提交恢复旧 task 和 unit；是否关闭
Resin request log 可独立决定，关闭日志不会改变代理、Platform 或 lease。
