# 统一 Resin Global/CN 池维护

本任务统一编排同一个 Resin 实例上的两个代理池：

- `Global`：`AppsGlobal` 平台和 `managed-apps-public-pool` 国际池。
- `CN`：`AppsCN` 平台和 `managed-apps-cn-public-pool` 中国大陆池。
- `Direct`：sing-box 的直连入口，不进入 Resin，不属于任何代理池，也不参与池节点选择。

`Global` 与 `CN` 共享 Resin 数据面、节点状态只读查询和写锁，但使用独立配置、候选源、地域门禁和 Platform。统一任务只负责调度和串行化，不把两种业务策略混成一个安全配置。

## 调度和失败语义

`resin-pool-maintenance.timer` 每小时 `:23` 触发一次，但跳过每天 06 点的系统升级窗口：

1. 每轮先维护 CN 池。
2. Global 池在每次 timer 触发时维护；timer 是唯一的调度间隔来源，统一锁只负责防止并发运行。
3. Global 主流程失败时回滚新 bridge generation，并保留上一版固定端口池，不把直接代理或临时来源写入同一 Resin subscription。
4. 任一分支失败都会写入统一状态并使 service 返回非零。
5. 用 `.maintenance` 锁防止维护实例重叠。CN 写入及 Global 发布使用同一把 `/run/lock/resin-pool-maintenance-data-plane.lock`，不会同时写 Resin；Global 下载、解析、DNS 和临时探测期间释放数据面锁。
6. 进入写入阶段才获取 `.priority` 排队锁，再最多等待数据面锁 780 秒。地区优选见到发布排队即跳过；等待超时必须报失败。重复维护实例不入队。

统一状态文件：

```text
/var/lib/resin-pool-maintainer/orchestrator-state.json
/var/lib/resin-pool-maintainer/last-unified-run.json
```

状态只保存 `run_id`、分支结果、时间和 Global 上次成功时间，不保存 token、Cookie 或代理明文。`last_global_success_epoch` 仅用于观测，不会阻止下一次 timer 触发的维护。

## Global 流程

每次 timer 触发时，任务按两阶段方式维护 Global：

1. 从主 JSON 来源和可选 Gist 来源获取候选，与当前槽位合并后重新验证。主来源下载失败仍复测当前池；健康槽位保持原上游和本地端口，失败槽位找到替代后在原端口更换上游。
2. `prepare-bridge` 生成新 generation 和 `prepared.json`，不切换 `current`。取得数据面锁后，`promote-bridge` 核对父 generation、30 分钟时效和文件摘要，再切换指针；`staged` 仅记录本轮临时回退位置。准备结果过期或父版本变化则拒绝发布。
3. 启动新 sing-box 后端并等待全部监听就绪，通过稳定 HAProxy 入口原子切换新连接，对非 CN 出口执行通用 HTTPS 门禁；先探测源中全部候选（`BRIDGE_CANDIDATE_LIMIT=0` 表示不在探测前截断），再把通过的节点最多纳入 1000 个固定槽位，不设置数量、相同出口或相对上一轮比例限制。没有替代的坏槽位仅为保持端口身份而留在 bridge 配置中，但不会进入 Resin 订阅。
4. 读取 Resin state/cache 的节点状态，更新并回读 `managed-apps-public-pool` 和 `AppsGlobal`。
5. Resin 验收成功后提交 bridge generation；任一步失败都切回本轮旧后端。旧代只在其客户端连接清空后退出，随后才允许清理文件。

promote、后端切换、check、sync、commit 及失败回滚位于同一数据面锁内。当 sync 仅读取当前 bridge 文件、禁止混入旧订阅，且 HTTPS/出口门槛一致时，check 委托给 sync 的写入前验证，省去重复全量探测；配置不等价则保留独立 check。发布后的复验和同步仍占锁，准备阶段并发不代表整个维护过程不阻塞。维护不再重启 bridge service 或对 sing-box 发 SIGHUP。HAProxy 保持入口监听，运行时 `set server bridge/current addr` 只改变新连接的目的地址，已有连接留在原后端；Direct 也覆盖在同一机制中。

`bridge_runtime.py` 作为 service 主进程管理 HAProxy 与后端。逻辑 `bridge.json` 和公开 SOCKS 端口保持不变；实际后端使用 `127.76.0.2–5`，每代端口相同，运行配置写在各自 generation 内。HAProxy server 不指定端口，因此继承入口目的端口，不需要额外预留端口范围。切换前按后端 PID 的 socket inode 核对全部监听，切换后回读 HAProxy 地址；回滚使用同一入口。

维护 service 必须允许写入 `/var/lib/proxy-region-latency`：切换前和回滚时的 `site-control enforce` 会更新 split 客户端池状态。漏掉该 `ReadWritePaths` 会在 `ProtectSystem=strict` 下触发 `EROFS`，阻断发布及事务收尾；部署 unit 后必须在真实 systemd 沙箱内验证权限和一次完整更新。此目录外的发布文件仍按原有边界保护。

最多同时保留四代。旧后端只统计自身监听地址/端口上的已接受 TCP 会话，连续空闲 10 秒才终止，避免上游空闲连接池阻止回收；未知 socket 状态不算空闲。四代都有会话时拒绝本轮切换并保留当前池，不以强杀长连接腾位置。单个活动后端崩溃时独立恢复，仍服务连接的旧代保持运行。启动和恢复均校验 generation 完整性。

`/var/lib/resin-singbox-bridge/runtime.json` 记录当前代、仍存活的旧代、入站连接数、切换次数和最后错误；旧代在此登记期间受 `prune_generations` 保护。上限是资源保护，持续长连接占满四代需从该状态定位，不能盲目重启。HAProxy 的 24 小时超时是无数据活动超时，持续传输会刷新它。

首次迁移需要安装发行版 `haproxy` 包，并用新 unit 替换旧单进程 unit；独立的发行版 `haproxy.service` 保持 disabled/inactive，由 bridge service 自己启动专用进程。首次接管旧监听有一次短暂重连窗口；后续正常维护不再重启入口。`BRIDGE_SWITCH_MODE=restart` 仅保留给恢复旧 unit 的显式迁移回退，生产默认 `graceful`。

本地真实集成验收（只访问回环 echo 目标，不使用生产凭据）：

```bash
BRIDGE_RUNTIME_INTEGRATION=1 PYTHONDONTWRITEBYTECODE=1 \
  python3 -m unittest discover -s tasks/resin-pool-maintenance/tests -p test_bridge_runtime.py -v
```

覆盖同一 TCP 会话跨两次切换与回滚、坏配置拒绝、四代容量保护、排空后恢复发布、活动后端崩溃不杀旧代连接。生产还需验证完整维护事务及公网 VLESS 链路；不能把回环测试当作用户网络测量。

## 可选 Gist 与协议链接来源

`BRIDGE_DISCOVERY_CONFIG` 指向 `discovery.json.example` 同结构的私有运行配置后，维护程序每 6 小时按 `Recently updated` 搜索 `vless://`、`ss://`，并复查配置中的公开 Gist ID。默认最多读取 4 个公开 Gist、每个最多一个文件，最多增加 300 个候选。候选缓存最多使用 24 小时，每小时仍重新做连接探测；来源失败不会延长缓存的新鲜度。

只允许 GitHub raw/Gist raw HTTPS，元数据只取 GitHub API 和 Gist 搜索；拒绝重定向、URL 凭据、非标准端口及非公网节点端点。无论 API 内容是否 truncated，均获取完整 raw 文件。解析复用 Resin 的 `cmd/subscription-converter`，接受 URI、Clash 和 base64 订阅，只保留 SS/VLESS/VMess/Trojan 连接参数，不导入规则、脚本、DNS、providers 或关闭证书验证的设置。

去重身份包括 TLS、Reality 和传输参数。额外候选先经过 sing-box 配置兼容检查，单个坏配置被隔离，再做公网 DNS 固定与真实 HTTPS 探测。Gist 命中、解析成功、TCP 可连都不等于双站订阅批准。

转换器单独编译部署，不运行时下载依赖：

```bash
cd /root/resin-repo
CGO_ENABLED=0 go build -trimpath -o /tmp/subscription-converter ./cmd/subscription-converter
install -D -m 0755 /tmp/subscription-converter /opt/resin-subscription-converter/bin/subscription-converter
```

候选与来源摘要保存在 `/var/lib/resin-singbox-bridge/discovery-cache.json`，权限 `0600`，不得进入 Git。停用 `BRIDGE_DISCOVERY_CONFIG` 即停止额外来源；已有节点仍按当前池的常规健康检查处理。

发现摘要 version 2 分开记录 `download`、`parse`、`metadata`、`search` 阶段与 HTTP 状态码，并区分 pinned/search/configured 来源贡献。原始解析异常和响应内容不写日志。空搜索明确标记，空候选不算来源成功；旧缓存升级时只提前重取一次，失败仍遵守原有 24 小时缓存到期，不通过重试延长新鲜度。

每个 bridge generation 还写入私有的 `slot-changes.json`：逐槽记录固定端口、`retained`、`replaced`、`retained_unhealthy` 或 `added` 状态，以及替换前后的 endpoint hash、失败类别和目标 host。它不保存上游凭据或原始 endpoint。当前维护轮使用 `run_id`，并通过 `bridge_generation` 与 `bridge_run_id` 关联到实际使用的 bridge；未生成新 generation 时，bridge 可能来自上一轮。

桥接端口由 sing-box 维护：Global 使用 1000 个稳定池槽位，从 `12000` 递增并跳过独立 Direct 的 `12400`，因此末槽为 `13000`；`12400` 仅用于认证直连入口。直连入口映射到 sing-box `direct` outbound，不创建 Resin sticky lease，也不占用 Global 槽位。

## 性能与端口保护

当前 2 核主机使用 `BRIDGE_DNS_WORKERS=16`、`BRIDGE_PROBE_WORKERS=32`、`BRIDGE_PROBE_BATCH_SIZE=64`；发布后检查与 Global 再验证也使用 32 并发、64 一批。仍扫描全部候选，不缩减 1000 个固定槽位，不降低目标成功门禁。TLS 探测共享每进程只读 SSLContext，避免每个目标重复加载 CA 库；证书和主机名验证保持启用。调低并发会延长等待型探测，但减少 CPU 竞争和更新期间的资源突发。

`sysctl-proxy-ports.conf` 对应 `/etc/sysctl.d/99-resin-proxy-ports.conf`，预留 `12000-13999,20000-29999`，防止内核临时出站端口占用生产监听和临时探测端口。部署前必须合并已有保留范围，不能覆盖其他应用的预留。默认探测起点 20000，可通过 `BRIDGE_PROBE_BASE_PORT` 配置；默认保留区最多容纳 10000 个同时映射候选，超出会在启动前拒绝，保留旧池。

临时 sing-box 启动日志仅写 root-only 临时目录；失败日志只返回端口占用、FD 上限、权限等类别，不泄露节点地址或密钥。临时进程结束后目录自动清理。

修改维护脚本必须等待维护 service 完成。Bash 会继续读取正在执行的脚本，原地改写可能造成中途解析错误；上线前先离线测试，再在空闲窗口发布。并发配置回退可恢复本次 `/root/deployment-backups/proxy-optimization.*` 中的 `maintenance.env` 和 `global-config.json`，不得在运行中替换脚本。

## CN 流程

CN 每轮从公开 CN HTTP 列表收集有限候选，执行：

- Cloudflare trace 必须返回 `loc=CN`。
- 华为连接检测、百度和哔哩哔哩通用 HTTPS 目标至少两个成功。
- 最低通过数与发布上限遵循 CN 配置；生产 `selection.max_nodes=30`，按独立出口去重。
- 失败时保留上一版候选文件和 Resin 订阅，不删除生产对象。

候选顺序为：先复验当前池，再轮流读取 CN 定向来源，最后轮流探索全球来源；维持 1500 上限。不会再让按文件名排在前面的全球大列表耗尽预算、挤掉 CN 来源。IPv4 与端口先做有效性检查，拒绝私网、回环和链路本地代理地址。journal 记录每个来源进入候选的数量，以及 `trace_failed`、`not_cn`、`https_failed`、`passed` 漏斗；CN 不足仍保旧并单独报告失败，不放宽地域或 HTTPS 门禁。

## 配置和运行时文件

- Global 配置：`/etc/resin-pool-maintainer/config.json`，权限 `0600`。
- CN 配置：`/etc/resin-app-pools/cn.json`，权限 `0600`。
- 统一环境配置：`/etc/server-scheduled-tasks/resin-pool-maintenance.env`，权限 `0600`。
- Admin token：由 systemd `LoadCredential=` 注入。
- Direct token：由 systemd `LoadCredential=` 注入。
- 运行时依赖和测试：本目录内 `lib/`，不依赖 Codex Profile 或技能目录。

Global 和 CN 的 `state_dir` 保持分开，便于按池隔离状态和审计；回退只在当前事务尚未提交时使用，不保留历史回滚副本。两个配置都指向同一个 Resin 数据面，但 subscription/platform 身份必须严格匹配各自配置。

## 离线验证

```bash
cd /opt/resin-operations/operations/tasks/resin-pool-maintenance
bash resin-pool-maintenance.test.sh
systemd-analyze verify systemd/resin-pool-maintenance.service systemd/resin-pool-maintenance.timer
```

离线测试不访问生产 Resin API、不访问真实代理、不读取生产 token。

## 部署和从旧任务迁移

迁移必须先停旧 timer，再安装新单元；统一 service 首次真实运行通过前不要启用新 timer，也不要删除旧状态目录或 bridge generation：

```bash
systemctl disable --now \
  resin-cn-pool-maintenance.timer \
  resin-pool-maintainer.timer

install -m 0644 systemd/resin-apps.service /etc/systemd/system/resin-apps.service
install -m 0644 systemd/resin-singbox-bridge.service /etc/systemd/system/resin-singbox-bridge.service
install -m 0644 systemd/resin-pool-maintenance.service /etc/systemd/system/resin-pool-maintenance.service
install -m 0644 systemd/resin-pool-maintenance.timer /etc/systemd/system/resin-pool-maintenance.timer
install -m 0600 resin-pool-maintenance.env.example \
  /etc/server-scheduled-tasks/resin-pool-maintenance.env
systemctl daemon-reload
systemctl start --wait resin-pool-maintenance.service
```

生产环境应从原 Global 环境文件精确迁移已审核的覆盖值，不要盲目用 example 覆盖现有参数。统一 timer 每轮都会执行 CN 和 Global；`last_global_success_epoch` 仅用于审计和监控，不参与是否执行的判断。

真实验收通过后再启用 timer：

```bash
systemctl enable --now resin-pool-maintenance.timer
```

旧的 `resin-cn-pool-maintenance.*`、`resin-pool-maintainer.*` 和 fallback 单元只在统一任务验收成功后删除。统一任务使用 `/var/lib/resin-cn-pool-maintainer/sources/` 和 `/run/lock/resin-pool-maintenance-data-plane.lock`；旧兼容目录及已退役的论坛 fallback 缓存可在迁移验收后精确清理。运行目录只保留当前轮；bridge generation 保留当前、事务指针和仍承载会话的旧代，旧代排空后在后续清理中回收。

## 生产验收

```bash
systemctl start resin-pool-maintenance.service
systemctl show resin-pool-maintenance.service \
  -p Result -p ExecMainStatus -p ActiveState -p SubState
systemctl show resin-pool-maintenance.timer \
  -p ActiveState -p UnitFileState -p LastTriggerUSec -p NextElapseUSecRealtime
journalctl -u resin-pool-maintenance.service -n 120 --no-pager
jq '{global_status, cn_status, overall_status, last_global_success_epoch, run_id}' \
  /var/lib/resin-pool-maintainer/last-unified-run.json
```

还应核对：Global 包含本轮通过门禁的非 CN 节点且不超过 1000；健康旧槽位保留原端口和 endpoint hash，只有失败槽位被原位替换；CN 数量符合配置、全部为 CN；bridge 没有遗留 `staged` 链接和 `prepared.json`；Direct 的 `12400` 认证 CONNECT 和 `direct` route 正常；`run_id`、bridge generation 和 Resin manifest 能直接关联。重复维护会成功跳过且不覆盖 `last-unified-run.json`，因此监控必须同时看 journal 和状态文件时间。

不要使用模型生成、Sub2API connection-test 或账号请求验证代理池；本任务只做 CONNECT/TLS、公开小流量目标和 Resin Admin API 回读。

## 回滚

若新 service 首次生产运行失败：

1. 保持 `resin-pool-maintenance.timer` 停用。
2. 确认没有维护进程持有 `/run/lock/resin-pool-maintenance-data-plane.lock`。
3. 使用 Git 中已提交的 unit、环境文件和 schedule 配置，执行 `systemctl daemon-reload`。
4. 不要删除或重建 Resin subscription、Platform、state 目录和当前 bridge generation。
5. 若本轮仍有 bridge `staged` 链接，先使用统一 helper 的 `rollback-bridge` 恢复当前事务，再启动任务；成功提交后不提供本地历史 generation 回退。

统一任务不生成 SQLite 备份。Global bridge 只在切换事务期间保留 `staged` 指针，提交或回滚后仅删除已经排空且不受 runtime 登记保护的旧 generation；CN 失败会原子恢复上一版候选文件。回滚入口本身不会把 Direct 加入任何 Resin 池。

## 设计依据

- [HAProxy 2.8 configuration](https://docs.haproxy.org/2.8/configuration.html)：server 未指定 port 时继承客户端目的端口。
- [HAProxy 2.8 management](https://docs.haproxy.org/2.8/management.html)：运行时 `set server ... addr` 和 server state 回读。
- [sing-box reload 源码](https://github.com/SagerNet/sing-box/blob/testing/cmd/sing-box/cmd_run.go)：不能把 sing-box 重载当作已有连接保留机制。

## Direct 边界

Direct 由 `resin-singbox-bridge.service` 作为独立入口提供。统一池维护任务可以在刷新 bridge 时确保 `12400` 直连入口仍被保留，但不把 Direct 计入 Global/CN 节点数、不对它做 Resin 订阅同步，也不在 Direct 失败时切换到代理池。
