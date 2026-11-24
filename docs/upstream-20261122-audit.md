# Resin 上游与残留源码审查（2026-11-22）

本记录保存 2026-11-22 的历史审查快照，不代表当前源码或 CI 状态。
2026-11-23 已完成上游与 mine 合并，当前结果见 [源码合并与职责收口](upstream-20261123-closeout.md)。
本记录不构成生产升级回执。

## 固定来源

本次实时 `ls-remote` 核验：上游 `Resinat/Resin:master` 为
`8e9f74edd09559c1ce2a50d64245ea6d18245729`；fork `origin/master` 为
`1a6954e71b0f25058d14f18d31a7a82276243f2f`，它是上游祖先，可快进；fork
`origin/mine` 为 `de5edca1bb4c34a9e9c36d10f530e8cc26cb8159`，定制基线为
`9b8ef8e5cf83071fbac4de29bd7187268b9cff7b`。canonical 当前 `mine=aad1b59` 落后
远端两提交，并有独有 `deploy/mine/docker-compose.yml` 的 `mem_reservation: 128m`
修改；同步前须保全并核对该修改，不能 reset。

生产仍受 `40f5204951cddad4cfb34d9a628c84be46094516` 的在线交接边界约束。
源码与生产并非同一代次，不能从 Git 合并结果推断运行升级完成。

## 上游升级的实际缺口

最新上游包含订阅代理链、relay 版本/健康反馈、请求日志 provenance 和 UI 改动。
重放个性化时必须在相同调用链同时保留上游 `NodeVersion`/`RoutingVersion` 检查、
chain relay 反馈及日志字段，并保留本 fork 的代次 CAS、严格租约、受限恢复和连接生命周期。
不能以旧文件覆盖上游新模块，也不能只处理 Git 冲突后宣称兼容。

存在必须先处理的 **状态迁移编号冲突**：

| 来源 | state migration 10 | cache migration |
|---|---|---|
| 生产 `40f5204`、显示名/retention/checkin/live 候选 | `000010_lease_display_names.up.sql` 创建显示名表 | 旧 cache schema |
| 最新上游 `8e9f74e` | `000010_subscription_chain_proxy.up.sql` 添加 subscriptions chain 字段 | `000003_nodes_dynamic_chain_proxy` 添加 node/latency chain 字段 |

仅把显示名 SQL 改名为 11 不足以升级生产库：旧库已经记录 version 10，普通 `m.Up()`
会把上游另一项 version 10 当作已完成，遗漏 chain 字段。候选现已加入启动前的 schema
指纹识别：只对可验证的旧 fork version 10 在事务内补齐上游 chain DDL；已是上游 schema
时只校验；部分、未知或 dirty schema 明确失败。version 11 再创建显示名表。回归夹具覆盖
fork schema 10、upstream schema 10、schema 9、重复迁移、部分 DDL 回滚和未知 schema。

这只解决源码层的迁移路径，不是 CI 通过或生产兼容验收。仍须由 hosted CI 对实际旧生产
schema 10、上游 schema 10、旧 schema 9 与首次建库执行完整验证，并确认显示名、订阅、租约
及 cache 数据保全、重复执行、失败恢复和新链路行为。当前候选尚未经过该 CI，也没有形成
可部署或已验收的产品版本。

## 残留分支的归属与价值

| 固定来源 | 仍有效职责 | 整理边界 |
|---|---|---|
| `origin/mine=de5edca` | CI/部署、代理恢复/严格租约/取消、原生任务目录；`b8a031e`/`de5edca` 的受限候选能力 | 作为 canonical 同步来源；与 `01893d4` 的有序候选池逐语义合并，不能互相覆盖 |
| `40f5204`（`2a48095`→`00374c5`→`40f5204`） | 显示名持久化、UI 查询、精确代次 if-empty CAS | 已有生产及原需求证据；写入 display 元数据，不改变 wire key/node/IP/lease timestamps |
| `3a465a4`、`d6b6829`、`199bdbe` | 全写者屏障、原生 authority/preflight、live bridge 与强状态持久交接 | 有效未来迁移依赖；未补齐旧 40f 的首跳，保留完整源码/证据，不据此执行生产切换 |
| `7e67f0a` / `0c38bda` | transport cooldown 上限 30 秒及现消费者语义边界 | 源自旧分类候选审查；不把 challenge 推断为凭据失效，不将未知业务请求重放 |
| `candidate-resin-checkin-candidates=5a4518a`，`01893d4` | 有序最多 60 个已验证候选、空池不替换、代次与共享预算、能力 API | 单独待集成；保留已有显示名与 CAS；不把匿名候选证明当带凭据业务成功 |
| `candidate-request-log-retention=65a5856`（`8c0aae1`、`fe85b55`） | 写入时间保留与有界 shard 清理、真实 WAL 回归、支持的 CI runner | 独立应用日志职责；需与上游 relay provenance schema 合并，不丢新日志字段或活动 WAL |
| `candidate-lease-schema-rollback=8572252` | 旧 schema 10 的恢复兼容候选 | 恢复来源继续保护；不能当新上游链路 schema 的通用 rollback 镜像 |

上表证明这些分支有可定位的职责，不代表各项已经合入新的 `mine`。现有显示名、迁移
候选和 checkin/retention 原需求分别见以下保留证据；清理前仍要核对最终主线语义、
工作树、原任务及恢复引用，并保存唯一历史。

- `/root/server-parallel-coordination-20261015/goal-C.md` 和
  `handoff/coordinator-to-C-resin-ownership.md`：显示名与稳定身份要求。
- `/root/session-closeout-20261025/resin-r01-r30-review.md`：分类冷却、显示名及旧源屏障审查。
- `/root/session-closeout-20261025/resin-live-final-conclusion.md`：真实双槽验证与旧源首跳限制。

本次策略提交只更新维护说明。没有编译、CI 产品验收、镜像发布、生产配置写入、重启或切流。
