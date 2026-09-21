# Resin 分支与部署约定

本 fork 使用两个长期分支：

- `master`：上游 `Resinat/Resin:master` 的干净镜像，不承载个性化改动。
- `mine`：生产源码分支，在当前上游基座上叠加经过验证的个性化改动，也是仓库默认分支。

`.github/workflows/sync-upstream-master.yml` 每天只快进同步 `master`。同步后应先审查
`master..mine` 与 `mine..master`，再把上游改动合并到 `mine`；不得自动覆盖生产个性化提交。

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
- `ghcr.io/wesperez/resin:mine`：Watchtower 使用的生产浮动标签。

候选分支构建（`candidate-*`）：

- 仅在全部 verify 通过后发布候选镜像，用于隔离金丝雀验证。
- 候选镜像仅包含分支名标签（如 `ghcr.io/wesperez/resin:candidate-*`）及分支名前缀的短 SHA 标签（`candidate-*-sha-<短SHA>`）。
- 候选发布绝对禁止打 `:mine` 或生产 `:mine-sha-*` 标签，避免触发生产 Watchtower 自动升级。
- 候选与生产构建使用各自的并发组和缓存域，候选运行不会取消生产发布，也不会写生产缓存。

镜像发布只发生在全部验证通过之后。服务器不安装 Go/Node，也不在生产机编译镜像。

## 生产部署

生产 Compose 使用 host network，以保持现有 `172.17.0.1:10834` 入口、自定义 endpoint
端口和宿主机 sing-box 出口不变。状态目录继续绑定现有路径：

- `/var/lib/resin-apps`
- `/var/cache/resin-apps`
- `/var/log/resin-apps`

Token 通过 `RESIN_ADMIN_TOKEN_FILE`、`RESIN_PROXY_TOKEN_FILE` 读取，不写入 Git 或镜像。
容器通过 `RESIN_RUNTIME_UID`、`RESIN_RUNTIME_GID` 使用宿主机 `resin-apps` 身份。

蓝绿部署时，固定入口 `172.17.0.1:10834` 由 conntrack DNAT 转发到两个槽位端口；
下游应用仍使用原地址。两槽必须使用独立的 state/cache/log 目录，inactive 槽启动前从
active 槽制作 SQLite 一致性快照。槽位必须显式设置：

```dotenv
RESIN_SHUTDOWN_PRESERVE_CONNECTIONS=1
RESIN_DRAIN_TIMEOUT=0
RESIN_STOP_GRACE_PERIOD=11m
```

`RESIN_DRAIN_TIMEOUT=0` 表示无限排空。双槽部署器先关闭旧槽自动重启，再发送 SIGTERM；
不用 Compose 的固定 stop timeout。旧槽停止接收新连接后保留已建立隧道，重复 SIGTERM
不会中断排空。若显式配置有限 drain timeout，Docker stop timeout 应大于该值。
旧槽不执行最终 cache flush；Watchtower 不得自动 recreate 任一槽位。

首次迁移使用声明 `io.resin.unlimited-drain=1` 的不可变候选镜像，保持 Watchtower 禁用。
在线快照、库校验、真实 CONNECT 与容器侧入口验证通过后，才把新连接切入 Blue。
旧版 Resin 在既有连接归零前保持运行；之后所有更新均通过双槽部署器执行。

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

### 已审核节点的单账号租约轮换

管理接口 `POST /api/v1/platforms/{id}/leases/{account}/rotate` 可同时传入
`preferred_node_hash` 和 `expected_target_ip`，将已审核的候选用于本次轮换。
`expected_node_hash` 与 `expected_created_at_ns` 仍断言旧租约，不能用候选值替代。

指定候选必须属于原平台当前可路由视图、健康、具有相同的已审核出口 IP，且满足
原有的节点/IP 排除条件。没有父租约也可选择；候选失效返回 `no_alternative`，
保留原租约及连接，不静默改选随机节点。旧租约已变更仍返回 `stale_lease`。
`preserve_connections`、租约 TTL 和 IP 负载统计沿用原语义；未传入这两个字段的
调用保持原选择行为。该接口不会修改平台策略，也不代表候选已通过目标站点验证。
调用方仍须在使用账号登录态前核验实际出口及站点响应。

## 回滚

生产始终记录当前镜像 digest、二进制版本和状态库备份。更新失败时：

1. 停止候选容器。
2. 恢复上一精确镜像 digest；若迁移已写入不兼容 schema，再恢复 SQLite 在线备份。
3. 验证 `10834`、管理健康接口、Platform、节点与 lease 后恢复流量。

不得删除 `/etc/resin-apps/admin.token`、`/etc/resin-apps/proxy.token` 或现有状态目录作为普通回滚步骤。
