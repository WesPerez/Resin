# 候选禁写启动与 authority（实验候选，非生产切换授权）

`resin fenced --transfer-id <32hex> --marker-sha256 <64hex> --authority-listen 127.0.0.1:<port> --deadline 2m`

仅消费相同候选 SHA 产生的 `candidate-preflight.json` 与两个独立停后数据库；默认状态/缓存目录必须分离、绝对、无符号链接、当前 UID 所有且仅 owner 可访问，数据库/marker 禁止 hardlink。操作者必须另行证明源已停止、完整恢复组与 exact hosted/image identity，并提供排他的 generation/mount。路径检查不是抵御 root/同 UID 外部写者的隔离措施。

## 生命周期

- 核 marker 摘要、transfer、candidate SHA、双库大小/摘要/quick_check、七字段集合、strong 逻辑摘要、有效配置；然后独占创建并 fsync `.candidate-authority-owner`，永不自动删除。
- immutable 只读双库构造**真实 runtime graph**，无迁移/repair/default 写，无 DNS graph/outbound warmup、观测文件、业务监听器或后台任务。过量 latency 必须已由 preflight 规范化，否则拒绝而不标 dirty。租约载入错误不可只 log 后继续。
- `GET /authority` 须 Bearer admin token，只读、脱敏摘要。只有 `fenced_ready` 才接受一次 `POST /authority/activate`，body 为 `transfer_id/instance_id/nonce`（nonce 为 32hex）；重复键/未知字段/超长 body 均拒绝。202 只是已持久接受，**不是 active**。
- `activation_pending` 的 durable nonce，随后 `activating` intent，均先于可写 DB/DNS/warmup/后台。此后新库可能取得权威，`writes_may_have_started=true`，绝不可用旧库回滚。关闭 immutable handle 后原地给同一 engine/repo 图接入可写句柄，不再次迁移/repair。
- 后台启动后仍关闭 HTTP/SOCKS 业务准入；join deadline/listener watcher，再持久提交 `active`，检查 deadline，然后才打开准入。任何失败/超时保持 `activation_unknown`/关闭准入，保留活写者与 DB，不以强杀或关闭仍写 DB 换退出。
- status 使用相同 instance/nonce 查询未知响应，禁止重放 POST。维护和退出复用原 join/flush/checkpoint 协议；authority 路径不允许旧 drain-only 的 Discard。正常退出也保留所有 restart fence。

## 精确限制

- activation deadline 使用 monotonic clock。构造、fsync、DNS 或内核不可中断 I/O 仍可能不能按时返回；watcher 可标记失败，不保证强制终止这些源，也不承诺保住 SIGKILL 时未 flush 的内存弱状态。
- 同进程 authority writer 的 fsync 卡住时，持锁 status 也可能不可用；没有回执就是未知。外部需保留维护，不能把磁盘上的旧 active phase 单独当活进程证明。
- 尚未接入部署器 fenced create/start、NAT CAS、active 后恢复或降级流程。普通启动与重复 fenced startup 均拒绝已 claim 的 generation。不得手删 marker 绕过。
- 旧生产 40f5204 不具备源协议；首次升级的全写源停止/最终 flush 因果前提仍未证明。所有测试只在 GitHub-hosted；本增量未授权生产切换，也未声称已经发生租约丢失。
