# Resin 源码合并与职责收口（2026-11-23）

本次将最新上游 `8e9f74edd09559c1ce2a50d64245ea6d18245729` 同步到 fork `master`，
把旧 `mine=de5edca1bb4c34a9e9c36d10f530e8cc26cb8159` 与基于该上游的职责候选合并。
最初的合并保留了两侧历史；随后按用户要求将最终个性化压成四条线性职责提交，
接在该最新上游基线后。旧完整历史与原合并 SHA `dddc065553ec0d478b5d990cc510141dab1bc7a2`
保存在已验证源码恢复档案中。首次重组业务源码和文件模式保持不变；后续迁移预检修复
按所属职责折叠，具体变更与 CI 证据一并保存在交付目录。
上游链式代理、版本隔离、relay 日志、AnyTLS、订阅解析与仪表盘采用上游实现。
最终提交、CI request、产物 digest、源码恢复档案和清理回执保存在
`/root/resin-source-closeout-20261123/`；这些字段与生产运行 SHA 分开核验。

| 原分支/提交 | 最终保留方式 |
|---|---|
| 旧 mine 的 CI、连接恢复、严格租约、探测取消和订阅转换器 | `c28a7aa`、`0ef9156`、`41ea4fd` 按最新上游适配，合并保留旧 mine 历史 |
| `40f5204` / 显示名与 exact-generation CAS | `abc9ccc` 与代理/服务职责保留；wire identity、节点、IP 和租约代次保持原合同 |
| `01893d4` / `5a4518a` 有序候选恢复 | 保留最多 60 个候选、显式空池不替换、能力 API、代次 CAS 和共享轮换预算 |
| `3a465a4`、`d6b6829`、`199bdbe` 维护/authority/live | `933facf`、`41ea4fd` 保留原生写入屏障、隔离恢复和 live bridge；生产交接另验收 |
| `7e67f0a` / `0c38bda` | 保留 30 秒传输冷却上限，应用失败仍按原分类边界处理 |
| `65a5856` 日志保留 | `b5ab8fc` 保留落盘时间与 WAL 保护，结合上游 relay provenance 字段 |
| `7a136f9` 源码维护规则 | 保留部署、canonical 同步和恢复合同；更新为 master 合并 mine 的维护流程 |
| `8572252` schema-10 rollback | 仅归入完整旧源码恢复档案，避免把旧回滚行为并入最新上游迁移 |
| `5a87641` 与未完成 merge | 完整归档提交、index、patch 和冲突文件；其中有效上游内容由最新 master 覆盖 |

最终四项职责为：CI/部署与源码维护合同，代理/租约恢复与显示名/schema 兼容，
原生维护/持久化屏障与 authority/live 交接，请求日志保留。上表中的旧提交号用于来源追溯，
不再作为 `mine` 上的碎片提交保留；最终四条完整 SHA 和 CI 产物见上述交付目录。

本轮修复健康接口与 `ApplyFeedback` 的版本/relay/error 传递、上游返回值变更的旧测试、
隔离启动 nil outbound manager、无写入回调的角色恢复，以及全部拨号失败后误提交未验证节点。
CONNECT 最多三次拨号全部失败时保留旧租约，只记录本账号观察到的传输冷却；不随机提交第四个节点。

`mem_reservation: 128m` 是已登记 Resin Compose 的现行配置，旧 canonical 脏修改与候选内容一致，
已进入部署职责提交。同步时先保全 patch/stash，再快进；内容一致后解除临时保全。

## 生产仍受正式交接门禁保护

已调用正式发布入口；它在镜像拉取、目标创建和 NAT 修改之前拒绝旧源首跳。
全程未停止、重启、写生产数据库或切槽。运行者仍是 `resin-apps-blue`，
OCI revision 为 `40f5204951cddad4cfb34d9a628c84be46094516`，镜像 digest 为
`sha256:266ed0e3955d6782501a592ebfb6d2f5e439fd8310d5dc446295c4b6aff4fbae`。

源码迁移已识别旧 fork state version 10 的显示名表与上游 version 10 的订阅 chain 字段冲突，
在事务中补齐可确认的旧 fork schema，version 11 保留显示名；未知、dirty、部分 schema 拒绝。
这不代表已验收生产数据。后续修复将 preflight 分成仅迁移与实际 bootstrap 两阶段：
只接受 committed SQL 精确匹配的 clean v9、upstream/fork/repaired v10 与 current v11；
未知表、索引、触发器、视图、列和默认值拒绝。原有强业务列的类型化行集逐字节保全，
新增 chain 字段必须全部为整数0，新增显示名表必须为空，已有 chain/labels 完整保留。
非法 UTF-8 TEXT 拒绝，避免 JSON 替换造成指纹碰撞。source_strong_logical_digest 单独留证，
strong_logical_digest 绑定批准迁移后的候选；bootstrap 默认写、修复及最终 flush 的额外强变更
仍然拒绝。authority 消费的是候选摘要，原始来源双库 hash 继续保留。历史版本的实际 SQL
夹具与篡改、重入、默认写入、authority 校验均交给 hosted CI。

当前旧 writer 仍没有正式 native final-write handoff。旧 preserve shutdown 先 Discard flush，
之后才停请求/后台写者，连接排空不能证明最后内存状态持久化；候选源码不能补进运行进程。
已安装冷交接器可消费上述候选摘要，但其源 native 证书门禁仍保留；live bridge 还直接比较
跨 schema 强摘要，本次修复没有改变 live 协议或宿主执行器。切换仍须有可核验的旧写者最终
写入回执、已登记发布锁/排空和完整恢复组，不能以 CI、健康或 TCP 归零替代。

后续真实数据库副本预检发现历史 missing-node 租约，默认 bootstrap 会清理这些绑定。
新增显式 `preflight --preserve-dormant-leases` 冷恢复选项，使用既有保全租约的 persistence
入口，只在该选项下允许合法、平台仍存在的 missing-node 历史绑定；不生成节点或 outbound，
不更改 node/IP、generation、expiry 或其他七字段。选项写入 receipt/marker，authority 从
已绑定 marker 继承；存在的节点仍须成功初始化 outbound，缺节点仅作 dormant 保留。
普通 preflight 继续拒绝会剪掉租约的 bootstrap；非法 identity、缺平台和业务行漂移仍拒绝。
该选项不冻结租约的正常到期/路由生命周期，也不产生旧源 native 最终写证书。

2026-11-23 用户允许短暂断线并要求直接部署最新版。已拉取精确 CI 镜像，并保全只读
在线双库副本、配置/凭据和 GeoIP；这些私有准备材料只是候选兼容性验证，不是停后权威
快照。当前正式宿主执行器没有 legacy cold import，且旧运行进程无最终 flush API。
停机部署仍须一个正式冷恢复事务及明确的数据恢复来源；不能把宿主生成的摘要伪称旧源
native handoff，不能通过修改 deployment.json、删 marker 或旧撤销入口绕过门禁。

宿主维护执行器继续由 `server-scheduled-tasks` 独占维护。最终 Resin 源码没有引用其旧不可达提交
`26fe5ac4e80848382d8c77c6e7835df8c3e3d9aa`；是否保留该仓库历史对象由宿主维护/恢复审查决定。
本次不读取或清理该仓库对象。
