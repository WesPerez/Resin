# Resin 运维模块

应用内计划仍使用原生调度器与设置页面；本目录维护属于本项目、但需要宿主机环境的独立执行器。
模块不导入业务请求处理层，也不把 Docker、浏览器和网络管理权限交给应用容器。

管理入口：**https://weesai.com/schedule/projects/resin/**。页面展示任务用途、计划、最近结果、
日志、配置预览和操作记录，并提供原生设置页入口。`project.json` 是本项目发布的管理契约。

## 目录与扩展

每个模块位于 `tasks/<name>/`，包含 README、脚本、测试、systemd 单元，以及适用的
`task.json`、`settings.json`、`results.json`。新增模块后，管理页按登记根目录自动发现，
不需复制算法到公共调度仓库，也不另启一套定时调度。

参数只开放脚本实际读取且有范围校验的字段。凭据、生产状态、账号映射和真实上游响应不进 Git；
已有 `/etc`、`/var/lib`、`/run/lock` 路径保持原样，避免割裂恢复链。

## 宿主机发布

1. 通过本项目 operations CI；应用源码有改动时，另外通过原有应用发布门禁。
2. 把本提交的 `operations/` 发布到 `/opt/resin-operations/operations/`，以 root 持有。
3. 在受保护的 `/etc/server-scheduled-tasks/schedules.toml` 的 `[projects]` 中登记
   `resin = "/opt/resin-operations"`。本项目计划条目带 `project = "resin"` 和相对来源。
4. 核对已安装单元与生产模式，再同步源码路径并 `systemctl daemon-reload`。
   沿用单实例锁、超时、配置与状态；不得自动开启已暂停的备用任务。
5. 核对源码、健康状态、执行日志和下一次时间。路径迁移不要求重建应用容器。

只在确需加载新代码时独立处理相应辅助服务；有活跃连接的代理数据面不能因运维源码迁移重启。
回滚使用本次部署前保存的受保护文件恢复点，恢复源码/单元/登记后再次核验。
