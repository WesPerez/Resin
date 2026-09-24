# Mine 生产部署

本 Compose 用于把现有 systemd Resin 迁移到 `ghcr.io/wesperez/resin`，默认复用当前
`resin-apps` 状态目录、`172.17.0.1:10834` 和宿主机 UID/GID。

首次 canary 在同目录创建 `.env`：

```dotenv
RESIN_IMAGE=ghcr.io/wesperez/resin:mine-sha-<40位提交SHA>
RESIN_WATCHTOWER_ENABLED=false
```

完成状态库备份、隔离端口验证和生产切换后，再改为：

```dotenv
RESIN_IMAGE=ghcr.io/wesperez/resin:mine
RESIN_WATCHTOWER_ENABLED=true
```

不要同时运行占用 `172.17.0.1:10834` 的 systemd `resin-apps.service` 与生产容器。
首次迁移和回滚步骤以仓库根目录 [BRANCH_DEPLOYMENT.md](../../BRANCH_DEPLOYMENT.md) 为准。
