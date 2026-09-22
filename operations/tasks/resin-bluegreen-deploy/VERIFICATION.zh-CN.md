# 2026-09-13 候选验收

## 候选

- Resin 源码：`edc8de4830f8809d08f394934e67cecb488372ed`，分支 `candidate-resin-bluegreen-20260913`。
- 镜像：`ghcr.io/wesperez/resin@sha256:3851bd0c24f3f3dd151d430bff56b68ec8f0185c0d61b96eeef1dc7095e1d8e8`。
- Resin CI：https://github.com/WesPerez/Resin/actions/runs/34706529405 ，Verify 和镜像发布成功。
- 部署 CI：https://github.com/WesPerez/server-scheduled-tasks/actions/runs/34706880662 ，18 项测试和 ShellCheck 成功。
- 最终 Resin 候选相对 `origin/mine` 不含 `webui/dist`，未混入其他任务改动。

## 本地验证

- Resin `go test ./...`、`go test -race ./cmd/resin ./internal/state ./internal/proxy ./internal/routing` 通过。
- Compose 渲染校验：`resin-apps-blue`、10835、独立目录、preserve=1、drain=0。
- systemd-analyze verify 通过；宿主原有 tat_agent PIDFile 警告与此任务无关。
- 两次隔离 netns 验证：本地构建二进制 349 条并发宿主新隧道 + 200 条两路径 burst 隧道，
  CI 镜像二进制 284 + 200 条；均零失败。保留的长连接跨首次迁移、blue/green 切换和回滚，
  仍能双向回显。旧槽两次 SIGTERM 后保持运行，客户端关闭后退出。NAT 恢复幂等。
- netns 无外网路由，测试数据库均为临时空库，使用本地 echo。CI 镜像仅创建了未启动的临时
  容器以提取二进制，提取后精确删除容器及其匿名卷。未运行生产模型请求。
- 单元测试覆盖部署前后故障、单次原子替换、首次迁移、rollback 失败、信号中断、preparing/pending
  崩溃恢复、拒绝复用、重复退休、锁释放、legacy 进程监听核验、WAL 一致快照、归档日志保留。

## 生产前置核验

当前 legacy 为 host network，地址 `172.17.0.1:10834`，镜像 revision `61564fc`。
候选验收期间未重启或替换它。state.db 没有启用的自定义 endpoint，已有 Docker NAT/conntrack
hooks。三个当前有效 UFW 来源为 docker0 / 172.17.0.0/16、br-80f67e94e214 / 172.18.0.0/16、
br-a6f4dc23562c / 172.20.0.0/16。firewall.py 只读计划生成 6 条槽位规则，失效网桥未带入。

尚未安装生产 `/etc/resin-apps/slot-compose.yml`、bluegreen.json、新 unit/timer 或 UFW hook，
未写生产 NAT/UFW。应按 README 的准备顺序安装，使用上述精确镜像执行 init。下游配置不变。

## 错误核验边界

2026-09-12 23:16:04 至 2026-09-13 00:16:04 +08，Sub2API 观察到上游尝试 400/502/524，
Router 的 provider-state 修复仍在触发。Router 记录 Astra 88 次 `response.completed`（57 次有
重试）；10 次 `response.failed` 是上游限流、超时或流失败，不能把 HTTP 200 当成成功。
两条 00:13 的具体失败在 400 修复后返回了上游 `rate_limit_exceeded`，不是 400 原样透传。
唯一顶层 400 是客户端 invalid_body。目标 provider-state 400 的客户端回归在此窗口未复现。

同一窗口 Guard 有 6 次轮换，未观察到轮换同秒伴随 502。524 仍有上游信号，代码修复不保证
外部服务错误清零。Resin CONNECT `http_status=0` 只表示传输层记录，不能用来统计应用成功率。

## 保证范围

当前结果支持“Resin 更新时旧连接排空、入口不变”。没有在生产做首次迁移、UFW reload、Docker
重启或整机重启试验。无损范围不包含主机/内核故障、外部上游中断或未启用 live-restore 的 Docker
重启。无限排空可能让旧槽长期占用，后续部署会等待；控制面改动不会跨快照窗口同步。
