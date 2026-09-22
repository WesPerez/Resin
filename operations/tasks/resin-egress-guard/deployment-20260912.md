# 2026-09-12 发布验证

## 发布内容

- Resin `61564fc04a74be09ad811f396b02e234a07e04c6` 已推送到 `WesPerez/Resin` 的 `mine`。
  [CI 34684936880](https://github.com/WesPerez/Resin/actions/runs/34684936880) 的全量 Go 测试、
  proxy/routing race 测试和镜像发布均通过。
- Resin 生产镜像固定为
  `ghcr.io/wesperez/resin@sha256:92e59e73719b7f9af2c0eaf4f4f980b21cd9f43d47d9050d47b9970071bf17f2`。
  524 轮换可保留已建立连接；省略 `preserve_connections` 仍执行原有关闭旧连接行为。
- Guard [PR #6](https://github.com/WesPerez/server-scheduled-tasks/pull/6) 合并提交
  `9d0ea0bd098dfbb1bfb24e6dfde2b756ed8b000d`，代码提交 `5c6f4c8397a49731e5e68be2e7ac6d6ca766f873`。
  固定运行目录 `/opt/resin-egress-guard/releases/9d0ea0bd098dfbb1bfb24e6dfde2b756ed8b000d`；
  本机 drop-in `/etc/systemd/system/resin-egress-guard.service.d/20-reviewed-release.conf`。
- Guard 59 项单元测试、Python 编译、Shell 语法和服务单元检查通过。独立审查覆盖日志恢复、
  CAS、并发和 524 保留连接契约，未发现发布阻断项。

本次恢复链路没有修改 Sub2API 源码，也没有重放业务请求或清除账号冷却。

## 运行验收

- 先部署 Resin，再部署 Guard。Resin 健康、重启计数为 0；Guard 写模式 active，重启计数为 0。
  运行文件 SHA256 与已审查源码一致。
- 首次迁移保留 182 个账号状态、17 条去重记录；pending、dead letter 和 rotation intent 均为 0。
  17:30 CST 再次重启 Guard 后，账号状态完全一致、去重记录保留，日志断点从 68649601
  推进到 68705854，未出现恢复错误或队列积压。
- 从 Sub2API 容器请求 `172.17.0.1:19085/healthz` 返回成功。
  MetAPI 容器最初超时，核实为缺少私网网桥防火墙规则；新增以下定向规则后返回 HTTP 200：

  ```sh
  ufw allow in on br-a6f4dc23562c proto tcp from 172.20.0.0/16 to 172.20.0.1 port 19085 comment 'MetAPI Resin egress guard feedback'
  ```

- 使用随机 `verify-preserve-*` 测试身份建立 SOCKS/TLS 连接，访问 Cloudflare 公开 trace。
  `preserve_connections=true` 轮换成功、`closed_connections=0`；旧连接仍能完成请求，
  新连接的节点、租约出口 IP 和实际公网 IP 均已变化。重复提交旧 CAS 返回 HTTP 409，
  新租约未再次改变。验证后关闭测试连接、删除测试 lease 并确认不存在，未触碰业务账号。

## 回滚与限制

发布前备份保存在本机 `/root/deployment-backups/resin-guard-durable-20260912` 和
`/root/deployment-backups/resin-preserve-20260912-1714`；私有配置、state、数据库和凭据不入库。
Guard 回滚时先停止服务并备份最新 state，恢复已验证的旧发布目录或 unit/drop-in，
保留累计去重和冷却状态，校验后再启动。Resin 前版 digest 为
`sha256:67774b1f80912530e1e844af4d17a612f57a5679ff409159f97794b7ab971ce1`；回退 Resin
前必须停用新 Guard 的 524 轮换，旧 API 不支持保留连接参数。

本次验收时 Watchtower 自身正常运行，Resin 的 `RESIN_WATCHTOWER_ENABLED=false`，
以固定 digest 发布，避免未经验证的浮动镜像自动替换。

换出口不能保证上游 524 消失；已有 TLS keep-alive 请求仍可能复用旧连接。
实时日志尾读是异步恢复机制，0.25 秒为轮询间隔，不保证每次客户端重试前均完成轮换。
已经缺失的 SSE 内容无法由守卫补回；自然流量恢复应结合后续成功请求与上游状态继续判断。
