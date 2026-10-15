# 租约显示名称与原标识兼容

租约页可设置显示名称（建议应用缩写 + 稳定账号或对象 ID），并同时显示原始账号标识。搜索框同时匹配名称与原标识；路由、释放租约和表格行身份始终使用原 `account`。同名记录通过原标识区分，名称不是身份凭据。

管理员接口：`PATCH /api/v1/platforms/{id}/leases/{account}/display-name`，请求 `{"display_name":"wd-account-42"}`，返回带 `display_name` 的原租约。空字符串清除名称；缺字段、控制字符或超过 128 字符返回 400，租约不存在返回 404。只写显示元数据，不调用 acquire、rotate、inherit 或 UpsertLease，不改 node_hash、出口、连接、created_at、expiry、last_accessed。

列表新增 `search` 参数，不区分大小写地匹配 `account` 或 `display_name`，在分页前过滤。原 `account`/`fuzzy` 参数保持旧语义，保护自动维护器按原标识读取租约的行为。按标识获取的接口及现有代理身份协议不变，`display_name` 是可选增量字段。

显示元数据暂不可读时，原列表/按账号读取仍返回底层租约，并附 `display_name_unavailable:true`，页面明确显示名称暂不可用。依赖显示名称的 `search` 返回明确错误，避免将不完整搜索误报为未找到；原 `account` 筛选仍可用。名称写入失败保持失败，不伪报保存。

state.db 的迁移 10 新建 `lease_display_names`，以 `(platform_id, account)` 为主键，与 cache.db 租约弱状态分离。名称随同一账号的租约续期、轮换、过期和重建保留；平台删除时级联清除。设置名称不更新平台时间戳，也不复制租约。生产发布通过已有蓝绿入口保留旧槽完整恢复组，不能用旧镜像直接打开已升级的新槽数据库。

批量规范现存名称前须确认应用/对象映射，逐条保存原 key、node_hash 与租约时间戳，并在更新后比较。已合规租约无需写入；未知归属不能按外观猜测。禁止删后重建或使用会覆盖目标的 inherit-lease 来美化名称。

验收在 GitHub-hosted CI 执行：v9→v10 迁移、关闭重开持久性、平台级联、名称编辑前后完整租约相等、旧/新名称搜索、旧 account 筛选兼容、认证与非法字段保护。WebUI 随镜像构建，发布后再核对实际页面和租约对照。
