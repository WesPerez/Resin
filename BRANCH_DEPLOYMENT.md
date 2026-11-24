# Resin 分支与部署约定

本 fork 使用两个长期分支：

- `master`：上游 `Resinat/Resin:master` 的干净镜像，不承载个性化改动。
- `mine`：生产源码分支，在当前上游基座上叠加经过验证的个性化改动，也是仓库默认分支。

`.github/workflows/sync-upstream-master.yml` 只快进同步 `master`。每次升级固定最新上游
SHA，在隔离候选审查合并差异并解决冲突。按原需求审查个性化模块，采用上游已覆盖
或更好的实现，其余有价值功能适配后重放到该上游基线。最终 `master..mine` 保持少数
线性职责提交，同功能的修复、测试和说明折叠到一起，不保留多轮 merge/fix 碎片。
职责、旧历史归档与本地源码同步要求见 [AGENTS.md](AGENTS.md)。

先保存旧源码恢复点，重新核验远端旧 SHA，再以精确 lease 发布已授权重组的 `mine`。
push 后用 `gci build .github/workflows/mine-image.yml --repo WesPerez/Resin --ref <branch>`
复用自动请求，跟踪原 request ID；仅明确没有自动事件或需要手动 inputs 时 dispatch。
最终提交 SHA 需要自己的 hosted 验证，不能复用别的分支/提交的产物。

发布源码后同步 canonical `/root/resin-repo`：确认没有未保全的本地修改或并发写入者，
fetch 远端，快进纯上游 `master`，将 `mine` 精确对齐已发布最终 SHA。历史重组后的
旧 tracking ref 不可作为 merge 基线；应校验记录的旧 SHA 后更新对应引用，保留本地
有效改动。最终记录 `HEAD`、`origin/mine`、工作区状态与生产运行 SHA。源码同步本身
不启动服务，也不替代运行身份和交接验收。

## 镜像

推送 `mine` 后，`.github/workflows/mine-image.yml` 依次执行：

1. WebUI 构建。
2. Go 格式检查与全量测试。
3. `internal/proxy`、`internal/routing` race 测试。
4. entrypoint shell 语法检查。
5. 构建并推送生产服务器使用的 amd64 GHCR 镜像。

发布标签：

- `ghcr.io/wesperez/resin:mine-sha-<40位提交SHA>`：精确版本。
- `ghcr.io/wesperez/resin:mine-<短SHA>`：便于人工识别。
- `ghcr.io/wesperez/resin:mine`：通过 CI 的浮动发布别名；生产槽仍绑定验收过的 digest。

候选分支构建（`candidate-*`）：

- 仅在全部 verify 通过后发布候选镜像，用于隔离金丝雀验证。
- 候选镜像仅包含分支名标签（如 `ghcr.io/wesperez/resin:candidate-*`）及分支名前缀的短 SHA 标签（`candidate-*-sha-<短SHA>`）。
- 候选发布绝对禁止打 `:mine` 或生产 `:mine-sha-*` 标签，避免触发生产 Watchtower 自动升级。
- 候选与生产构建使用各自的并发组和缓存域，候选运行不会取消生产发布，也不会写生产缓存。

镜像发布只发生在全部验证通过之后。服务器不安装 Go/Node，也不在生产机编译镜像。

## 生产部署

生产 Compose 使用 host network，以保持现有 `172.17.0.1:10834` 入口和宿主机出口。
Blue/Green 分别使用 `10835`/`10836` 与 `/var/{lib,cache,log}/resin-slots/{blue,green}`
的独立目录。旧 `/var/{lib,cache,log}/resin-apps` 仅按既有恢复归属处理，不能用于
新建平行生产实例或覆盖当前槽数据。端口、endpoint、网络和权限以正式配置及发布器校验为准。

Token 通过 `RESIN_ADMIN_TOKEN_FILE`、`RESIN_PROXY_TOKEN_FILE` 读取，不写入 Git 或镜像。
容器通过 `RESIN_RUNTIME_UID`、`RESIN_RUNTIME_GID` 使用宿主机 `resin-apps` 身份。

固定入口由 conntrack DNAT 转发到两个槽位端口；下游应用仍使用原地址。2026-11-25 起常规更新必须保护旧 TCP，使用正式部署器的滚动双槽路径，不要求实验 native 交接证书。

1. 获取最终 hosted CI 的完整 SHA 和镜像 digest，持已登记发布/数据锁。
2. 记录事务，持久冻结旧槽已提交的管理配置；使用 SQLite 在线 backup 保存 state/cache 数据库及已提交 WAL，旧代理流量继续工作。
3. 仅在独立副本执行候选 `resin migrate`，使用同一套原生迁移，并核验既有业务行和租约七字段。
4. 新槽在放流前隔离，验证本地健康与代理 CONNECT/TLS；新旧数据库和日志目录必须独立。
5. 新槽就绪后原子切固定入口的新 TCP，登记新 active 与旧 draining；旧连接自然结束后才停止旧实例。放流后可能已有新业务写，失败不得盲目倒灌旧库。

普通槽使用 `RESIN_PRESERVE_DORMANT_LEASES=1`，保留合法未过期的失联节点租约；缺节点仍不可路由。发布器不向仍有连接的旧实例发送停机信号，仅在 accepted socket 和精确 conntrack 均为空后普通 stop。旧槽排空期间的弱状态不回并新库，已提交配置、显示名和业务数据库由源配置冻结及在线快照保护。

普通部署保留完整备份、原生迁移、放流验收和真实旧连接排空。实验性的
native final-write、authority、fenced、live 证书与启动 marker 已退役，
不再提供平行交接入口。已有恢复文件仍按真实数据归属处理。正式唯一入口为 `/opt/server-scheduled-tasks/runtimes/resin-bluegreen/current/resin-bluegreen-deploy.sh`；执行器源码、恢复与验收由 `server-scheduled-tasks/tasks/resin-bluegreen-deploy/README.md` 统一维护。

## 个性化恢复边界

生产显式配置：

```dotenv
RESIN_PROXY_CONNECT_TIMEOUT=10s
RESIN_PROXY_CONNECT_RETRIES=2
RESIN_PROXY_TUNNEL_FIRST_BYTE_TIMEOUT=10s
```

- 拨号失败只在 CONNECT/SOCKS 成功响应前最多重选两次，总计三个物理节点，不缓存请求体。
- 重选保留 Platform/Account 逻辑身份，并排除本次连接中所有已经失败的物理节点。
- lease 删除使用 expected `node_hash` 比较，旧失败请求不能删除并发产生的新 lease。
- 客户端开始发送隧道数据后，10 秒没有任何上游字节才关闭连接并失效旧 lease。
- 收到任意上游字节后不再使用该超时；模型首 token 或长推理不属于 Resin 的判断范围。
- Resin 不重放已进入加密隧道的业务请求。安全业务重放由拥有 L7 语义的上层服务负责。

### 下游偏好与旧格式兼容

管理轮换和代理恢复接口接受可选候选节点提示。空、重复、失效候选及旧 IP
观察不阻断正常平台池；偏好用尽后按现行健康与平台配置正常选择。
失败回执仍比较原账号观测的节点与分配版本，防止旧结果修改新租约。

旧 `Platform.Account~r1~node~version~deadline~ip` 用户名按基础账号正常路由。
后缀不再钉住节点、IP 或连接期限，也不禁止正常重选、bypass 或恢复。
`lease_guard_version: 1` 保留旧格式接收兼容；新客户端使用稳定的
`Platform.Account` 即可，不需要同步修改其它项目。

## 回滚

生产始终记录当前镜像 digest、二进制版本和完整状态恢复组。更新失败时由现行发布器
按已持久化事务和权威归属恢复；不能盲目倒灌旧库。常规检查包括：

1. 停止候选容器。
2. 校验仍有恢复资格的源码与完整状态组；不兼容 schema 需要先验证对应迁移恢复合同。
3. 验证 `10834`、管理健康接口、Platform、节点与 lease 后恢复流量。

不得删除 `/etc/resin-apps/admin.token`、`/etc/resin-apps/proxy.token` 或现有状态目录作为普通回滚步骤。
本机镜像只保全部运行槽实际使用的版本，旧镜像由统一回收器处理；源码/数据恢复组
不属于镜像备份，不为 rollback 再保留 previous、Debug 或 first-switch 镜像。
