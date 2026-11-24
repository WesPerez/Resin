# Mine 生产部署

正式入口由 `server-scheduled-tasks/tasks/resin-bluegreen-deploy/` 唯一维护，固定 `172.17.0.1:10834` 和独立槽目录。

正常 `deploy <已验证镜像digest>` 使用保连接双槽更新：冻结旧槽已提交的管理配置，SQLite 在线 backup 双库/WAL，在独立数据与日志目录迁移、启动并验收新槽，再切固定入口的新 TCP。旧实例继续服务已有连接，只在 accepted socket 和精确 conntrack 均为空后停止；有连接或读取未知时等待，不强杀、不提前复用。无需实验 native final-write 证书。旧排空弱缓存不倒灌新库；新槽设置 `RESIN_PRESERVE_DORMANT_LEASES=1`，保留合法失联节点租约，节点不可用仍不能路由。

正式入口为 `/opt/server-scheduled-tasks/runtimes/resin-bluegreen/current/resin-bluegreen-deploy.sh`。源码、恢复和验收统一由 `server-scheduled-tasks/tasks/resin-bluegreen-deploy/README.md` 维护，不能使用普通 Docker/Compose 停启替代。

两槽禁止 Watchtower 自行替换；生产始终绑定最终 hosted CI 的精确 digest。配置、认证、日志和数据库保留原归属。详见 [部署约定](../../BRANCH_DEPLOYMENT.md)。
