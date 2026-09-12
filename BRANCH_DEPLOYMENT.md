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

首次迁移必须先使用精确 `mine-sha-*` 镜像并禁用 Watchtower 标签完成 canary。状态库在线备份、
`integrity_check`、入口健康、节点数、Platform、lease 和自然传输事件均验收后，才切换到 `:mine`
并启用 `com.centurylinklabs.watchtower.enable=true`。

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

## 回滚

生产始终记录当前镜像 digest、二进制版本和状态库备份。更新失败时：

1. 停止候选容器。
2. 恢复上一精确镜像 digest；若迁移已写入不兼容 schema，再恢复 SQLite 在线备份。
3. 验证 `10834`、管理健康接口、Platform、节点与 lease 后恢复流量。

不得删除 `/etc/resin-apps/admin.token`、`/etc/resin-apps/proxy.token` 或现有状态目录作为普通回滚步骤。
