# Resin 双槽部署

下游继续使用 `172.17.0.1:10834`。Blue 监听 `10835`，Green 监听 `10836`。
PREROUTING 和 OUTPUT 各有固定入口规则，跳入 `RESIN_BLUEGREEN`；链内只有一条 TCP
DNAT 规则，切流仅执行一次 `iptables -R`。已有连接由 conntrack 保持原映射，新连接进入新槽。

已于 2026-09-13 完成生产首次切流，2026-09-15/16 复核通过。生产状态、提交归属和保证范围
见 [收尾审查记录](REVIEW-20260916.zh-CN.md)；历史候选测试见 [候选验收](VERIFICATION.zh-CN.md)。

## 排空与数据

- 新槽先通过 Compose 隔离检查、健康检查、宿主及消费容器网络空间内的真实 CONNECT/TLS/HTTP
  检查，再切流；切流后重新检查固定入口，失败则回切并排空候选。
- 第一次迁移在线启动 Blue，legacy 继续监听 10834。所有非 LISTEN TCP 状态归零后才停止
  legacy。旧 keep-alive 可以继续承载请求，因此旧实例可能长期保留。
- 后续更新为旧槽设置 `restart=no`，发送 SIGTERM。镜像必须声明
  `io.resin.unlimited-drain=1`，实际环境必须为 `RESIN_SHUTDOWN_PRESERVE_CONNECTIONS=1`
  和 `RESIN_DRAIN_TIMEOUT=0`。这里的 0 表示无限排空。重复 SIGTERM 不会终止排空。
- 部署器不使用 `compose stop` 的固定超时；`stop_grace_period` 只影响其他人工停止途径，
  不能把人工 Docker/Compose 重启当成无损更新。
- 旧槽仍运行、有未关闭 TCP、或保留退休记录时，拒绝下一次复用该槽。维护 timer 每 15 秒
  检查一次，无后台部署进程、无长时间持有部署锁。
- 每槽独立 `/var/{lib,cache,log}/resin-slots/{blue,green}`。`state.db` 和 `cache.db` 使用
  SQLite 在线备份并执行 quick_check，不复制 WAL；country.mmdb 一并复制；metrics 和请求日志
  从空目录开始。复用槽时旧代目录移动到各根目录的 `archive/`，不会被清除或合并。
- 快照至切流期间不要修改平台、订阅、endpoint 等控制面配置。旧槽后续 cache/lease 变化
  不合并到新槽；此策略不提供两个进程的实时状态复制。

`/var/lib/resin-slots/deployment.json` 是唯一权威记录，原子写入并 fsync。它记录 active 容器 ID、
image digest、preparing/pending 事务和 draining 列表。发生 SIGTERM 或进程异常退出后，
`reconcile` 根据记录恢复路由并继续排空。不能手工改 active 指向已经开始排空的实例。

## 上线前准备

依赖：Python 3 标准库、Docker Compose v2、iptables、iproute2、nsenter、UFW。
必须使用已通过 CI 的不可变候选镜像；生产机不构建镜像，不直接推送 Resin `mine`。

1. 安装本目录到 `/opt/resin-bluegreen/releases/<commit>`，`/opt/resin-bluegreen/current` 指向该版本。
   把候选 Resin 仓库的 `deploy/mine/docker-compose.yml` 安装为
   `/etc/resin-apps/slot-compose.yml`，保留现有 legacy Compose 原件。
   脚本会校验渲染结果的 project、container_name、端口、目录、Watchtower 和排空环境。
2. 根据 `bluegreen.json.example` 准备 `/etc/resin-apps/bluegreen.json`。`clients` 必须覆盖真实消费
   网络，例如 Sub2API、Antigravity、MetAPI；探测使用现有 token 文件，不把 token 放入命令行。
   探测只 GET 指定 HTTPS 健康目标，不调用模型、不执行业务工具。
3. `python3 firewall.py` 只打印规则计划；`--apply` 才放行。规则只镜像现有 10834 的 UFW
   来源权限，且只匹配当前实际存在的 bridge，不沿用失效网桥名。先放行两个槽端口再切流。
4. 审阅并备份 `/etc/systemd/system/resin-apps.service`、现有 NAT/UFW 和 legacy container inspect。
   安装本目录的同名 service、新 nat service/timer 并 daemon-reload。替换旧 unit 后不要执行
   `systemctl restart resin-apps`；新 unit 的停止动作为空。启用 timer，让中断后的事务有恢复入口。
5. 将 `ufw-after-init.fragment` 合并到 `/etc/ufw/after.init` 已有的 start 分支，保留现有
   Docker ingress policy 调用。正常 UFW reload 后异步触发恢复，timer 也提供补偿。
6. 安装本候选配套的 `resin-pool-maintenance/lib/resin_pool_sync.py`。在 Global/CN 维护配置的
   `resin` 对象中添加 `deployment_record: /var/lib/resin-slots/deployment.json`。维护任务据此
   读取 active 记录中的唯一 `cache_db`；第一次迁移前沿用原配置，切流恢复未完成时拒绝对账。
   将本目录 `resin-pool-maintenance.conf` 安装为维护 service 的 drop-in，允许以现有 resin-apps
   组读取槽目录，并允许 SQLite 打开活动 WAL 数据库所需的共享内存锁。快照目录与文件分别为
   0750/0640。部署与维护沿用同一个 data-plane lock，不同时变更控制面。

上述安装、UFW 写入及生产切流应在候选验收后执行。本目录不会在测试时自动安装或改生产规则。

## 执行

```bash
./resin-bluegreen-deploy.sh init ghcr.io/wesperez/resin@sha256:<候选digest>
./resin-bluegreen-deploy.sh status
./resin-bluegreen-deploy.sh deploy ghcr.io/wesperez/resin@sha256:<下一候选digest>
./resin-bluegreen-deploy.sh reconcile
```

`init` / `deploy` 由宿主 root 直接执行，数据面验收需要 `nsenter -n` 权限。
现有 systemd unit 只运行 `start` / `reconcile`，没有授予部署探测所需的 `CAP_SYS_ADMIN`；
不要直接把 `ExecStart` 改为 `deploy`。

`start` 只启动记录中的精确 active 容器并恢复入口；容器丢失时会报错，不根据浮动标签创建替代。
开机由 resin-apps.service 执行，Docker 重启通过 PartOf 及 timer 恢复。已经成功切流后如需回滚，
等退休槽可复用，再用旧镜像 digest 执行一次 deploy，从当前 active 快照数据。

首次迁移要求 legacy 会话建立前已有 NAT/conntrack hooks；当前 Docker 宿主符合这一前提。
脚本拒绝在完全没有 NAT target 的主机上首次迁移。不得 flush conntrack 或整张 NAT 表。
这里保证的是 Resin 应用更新；主机重启、内核故障和当前 live-restore 未启用时的 Docker 重启
仍可能断连接。自定义 endpoint 会与另一个 host-network 槽抢端口，当前版本发现启用的自定义
endpoint 就拒绝部署；当前生产库没有此类 endpoint。

## 验证

```bash
./resin-bluegreen-deploy.test.sh
python3 netns_e2e.py --binary /absolute/path/to/test-resin
```

单元测试模拟 Docker/iptables 故障，覆盖首次迁移、原子回切、信号中断、preparing/pending 恢复、
回滚失败保留双方、复用拒绝、锁释放和 SQLite WAL 快照。内核验收使用两个临时网络空间，
运行三个真实 Resin 进程和本地 echo，覆盖两种入口路径、首次迁移、反复切换和回滚、重复
SIGTERM、双向 CONNECT 和幂等规则恢复。无外网路由，不访问生产 Docker、NAT 或业务数据库。

生产候选验收、UFW/unit 安装和首次切流已完成。今后更新使用固定发布目录的 `deploy` 命令，
不要通过 `docker restart`、`compose down` 或带停止超时的重建来替代。归档目录的保留
与清理须另行按业务审计需求决定；本任务不自动删除历史日志。
