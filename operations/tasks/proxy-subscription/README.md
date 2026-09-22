# proxy-subscription

设计取舍、故障修复与验证依据见
[2026-09-18 审查记录](../../docs/reviews/proxy-subscription/audit-2026-09-18.md)
和 [2026-09-20 整改验收](../../docs/reviews/proxy-subscription/remediation-2026-09-20.md)。

## 当前：普通上网与双站严格池分开

生产 `rotation-policy.json` 的 `mode=split` 继续使用原来的严格双站浏览器门禁，但发布用途分开：

- `PROXY`、`Auto-Fast`、`Auto-Rotate` 使用 `Global-Auto` 和六个 `*-General` 固定 VLESS 身份，后端是独立的 `ClientGeneral*` Resin 平台，仅选择通过 Global 通用验证的池。两个自动组每 60 秒检查当前逻辑节点，后端成员随服务器池更新。
- `linux.do`、`ldstatic.com`、`agentrouter.org` 的域名规则固定走 `Site-Strict`，其默认节点为 `Sites-Verified`。`ClientSites` 平台仅匹配当前有效、经过两轮浏览器和公网订阅身份校验的出口；池空时服务器 `DENY`，不回退到普通出口。
- `Sites-Verified` 身份长期保留。服务器替换合格出口后，已缓存的客户端配置无需等下一次订阅下载就能使用它。旧的逐出口 `US-01` 等仅作为严格组中的手动选择，手选过期节点仍需改回 `Sites-Verified`。
- 新增 SOCKS 路由使用 `Platform.profile`，启用 Resin sticky lease；不使用会逐连接随机换 IP 的空 account。租约仍受平台有效成员和熔断约束，不能绕过撤销。

客户端首次迁移需更新原订阅，在规则模式下将 `PROXY` 选为 `Auto-Fast`，将 `Site-Strict` 保持为 `Sites-Verified`。客户端可能保存旧选择，刷新后应核对这两项。普通网络正常不代表双站永久免验证。

`/etc/xray/client-pools.json` 是私有身份清单，不进入 Git。`provision-client-pools.py --install` 为已有 WS 入站增加专用身份和精确 user 路由，先创建关闭的平台、测试配置，再重启一次 Xray；不会把原主身份的服务器直连当作 Global 池。之后资格变化只更新 Resin 平台，不再重启 Xray。清单、配置与订阅备份位置在安装输出中记录。

`/var/lib/proxy-region-latency/client-pools-status.json` 记录各池可路由数、严格名单版本和更新时间。严格策略、常规连通性、订阅下载成功率是三个不同指标。

安装后使用 `provision-client-pools.py --activate`：先验证 Xray 归属、更新独立平台并运行真实公网 Mihomo 预检，通过后才切换 `mode=split` 并原子发布；失败恢复旧策略。严格池为空时允许启用普通网络，严格入口继续关闭。

`proxy-client-health.timer` 每五分钟先通过 HTTPS 拉取真实订阅并核对发布内容，再使用隔离 Mihomo，经本机公网 TLS/WS/VLESS 入口检查 Global 与 Sites-Verified 的 Cloudflare trace、Google 204 和再次 trace；前后出口必须一致且属于对应有效池。结果写 `client-health.json`，不写凭据或出口 IP。检查期间版本变化标记 `inconclusive`，不计作成功。该拨测覆盖服务器公网入口到出口，未覆盖用户设备到服务器的网络，也不代替两轮浏览器页面门禁。

拨测 timer 与本任务的 region/site timer 一样独立部署，不由全局 `schedules.toml` 接管。激活 split 后安装并启用：

```sh
install -m 0644 /opt/resin-operations/operations/tasks/proxy-subscription/systemd/proxy-client-health.{service,timer} /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now proxy-client-health.timer
```

设计参考：[Mihomo 代理组](https://wiki.metacubex.one/config/proxy-groups/)、[Google SRE 监控](https://sre.google/sre-book/monitoring-distributed-systems/)。正常更新的连接保留与资源保护见 [池维护说明](../resin-pool-maintenance/README.md)。

## 历史模式与当前严格池共用的双站质量门禁

`/etc/xray/rotation-policy.json` 的 `mode: unified` 启用本节策略，原订阅 URL 保持不变。
本节的三个组与全站规则仅适用于旧 `unified` 模式；生产 `split` 的发布和客户端选择见首节。
下文浏览器证据、资格期限、隔离和续期机制仍用于 `split` 严格池，日期章节保留历史运维记录。

- `PROXY`：选择 `Auto-Fast`、`Auto-Rotate` 或手选某个合格节点。
- `Auto-Fast`：`url-test`，每 300 秒测速，150 ms 切换容差，尽量保持当前出口。
- `Auto-Rotate`：`load-balance / sticky-sessions`，同一来源 IP 和目标主域约 10 分钟保持出口；
  新会话重新分配，可能仍抽到相同 IP，既有连接不强制中断。

两种策略使用完全相同的独立出口集合，所有网站跟随 `MATCH,PROXY`。
普通浏览器和指纹浏览器均可使用相同策略；同一电脑的不同窗口不等于不同来源 IP，
因此不保证逐浏览器分配不同出口。LDStatic 与 LINUX DO 是不同主域，轮换时可落在不同合格节点。
客户端完整更新订阅，在规则模式的 `PROXY` 中选策略即可，无需另配端口。

目标容量 US 8、HK 4、SG 4、JP 4、DE 2、NL 2，实际数量取决于当前双站通过数。
不会为了凑足十几个节点放宽页面门槛。每个节点对应独立 VLESS UUID、Browse 平台和精确
bridge 路由，按实际 IP 去重。每平台禁用自身流量引起的被动熔断；已通过页面检查的出口
不会仅因全局累计失败次数提前撤下。其他 Resin 平台仍可能触发共享节点的全局熔断，
实际不可路由时仍关闭该槽位，等待上游健康恢复。

新候选先通过独立、不公开的 `BrowseCheckXX` 身份连续两轮浏览器测试，再绑定公开槽位，
并复测该槽位的真实 UUID。所有测试均经过 Mihomo -> 公网 TLS -> Xray -> Resin，
沿用订阅 DNS。页面覆盖论坛首页、AgentRouter 登录入口和注册页，要求真实内容、无验证码、
首屏不超过 18 秒、核心脚本/CSS/必要数据请求完成，且正常状态持续至少 3 秒。
导航提交后直接观察页面状态，图片、遥测和长轮询不阻塞通过判定。
检测不会点击或拖动验证码。传输日志失败率不是页面失败率，HTTP 200 的验证码页也算页面失败。

通过证据绑定地区、端口、node hash、上游配置 hash、实际 IP 与所选槽位，有效期 90 分钟；
最后一轮证据必须来自公开槽位，续期允许两轮公开槽位复测；仅检测路由的报告不能发布。
30 分钟后安排复测；距证据到期不足 15 分钟的最先处理，随后最多安排两个新候选，再处理距到期不足 30 分钟的续期和其余复检。其余队列每两次复检穿插一个新候选，避免新增节点排在时间预算之外。
每轮最多 8 个候选、约 11 分钟，结束后 3 分钟继续下一批。两轮续期预留 270 秒，
三轮新候选预留 390 秒；余下时间不足以检查新候选时，仍可处理预算内的续期。
与上游维护共享数据锁，每候选结束释放；忙时延后，不抢占上游更新。
补池优先复查同一身份下近期且晚于最近失败的通过记录，但历史记录不替代本次完整测试；同分时优先未测候选，再按地区空缺容量安排。已冷却的失败候选不会持续遮住未测节点。
某个必须通过的页面失败后立即停止该候选的后续页面检查；缺少页面仍判失败，验证码隔离规则保持不变。
同 IP 的不同线路先按页面证据排序，再去重分配，避免测速较快的别名遮住已经通过浏览器检查的线路。
未入池候选的首次临时错误 5 分钟后可重试，重复错误冷却 30 分钟。
首次临时错误可保留尚未过期的旧审批；验证码、重复失败、IP 漂移会隔离，并撤下受影响出口。
隔离按真实 IP 记录，不能换端口绕过。身份更换、证据过期或无健康路由时关闭服务器侧槽位，
旧客户端缓存不会回落到未经检查的节点。零通过时两个策略均为 `REJECT`。

90 分钟到期由后台 `enforce` 执行撤销，Resin 请求本身没有审批到期字段。维护发布阶段持锁、任务异常或后台停止可能延迟撤销，不能当作严格的请求级 TTL。客户端测速间隔也不是订阅更新间隔，用户设备仍需开启定时拉取订阅。

订阅 Nginx location 返回 `Cache-Control: no-store` 与 `profile-update-interval: 1`，后者建议支持此响应头的客户端每小时拉取。Clash Verge Rev 按小时解析，但已有更新间隔和关闭自动更新的设置优先；首次导入或再次拉取后才可能采用提示。服务器不能保证所有客户端接受此值。配置模板见 `examples/nginx/proxy-subscription.conf.example`；上线前检查 `nginx -t`，仅在通过后 reload 并核验公网响应。

主要入口：`rotation-control.py provision` 备份并创建身份；`unify` 验证并切换；`refresh`
续期和补充；`enforce` 清理检测路由、约束资格并重新发布。生产 timer 为
`proxy-rotation-quality.timer`；旧 `proxy-site-quality.timer` 已退役，资格约束由共享维护流程继续执行。
浏览器复测每轮结束后间隔 3 分钟（另有 0–15 秒抖动）；30 分钟提前续期、90 分钟证据期限和
页面性能判定保持原值。采用 `CPUWeight=20`，保留单核 CPU 配额，避免硬限过低把正常节点误判为慢节点。
该周期仅用于代理页面质量复测，与 Sender 的每秒容量重试无关。
`proxy-region-latency.timer` 保留五分钟资格约束。浏览器代码部署在 `/opt/proxy-site-quality/`，
以 `proxy-site-browser` 用户运行，systemd 必须允许其状态目录写入与降权。
每轮日志中的 `site_qualified` 以实际路由约束后的数量为准；状态文件可能保留尚未过期但暂时不可路由的证据。

凭据在 `/etc/xray/rotation-slots.json` 和 `rotation-audit-slots.json`，状态与证据在
`/var/lib/proxy-region-latency/rotation-state.json`、`unified-client-*.json`，截图在
`/var/lib/proxy-site-browser/`；均不进入 Git。`verify-rotation-subscription.py` 校验公网文件、
三个组、全池真实出口、两个策略的双站页面、同会话粘性与不同来源会话的分配，
证据为 `rotation-acceptance-*.json`；`trace_checks` 保留每次出口查询的阶段、来源、HTTP 状态、
curl 错误、耗时与 IP，包括失败前已经完成的查询，不重试掩盖失败。
验收遇到能明确归因到单出口的页面失败时，在已有数据锁内写入同一隔离状态、约束路由并重新发布，失败报告仍保持失败。首次临时错误仍遵守现有宽限规则；选择发生变化或自动轮换无法确定具体出口时只保留证据，不能盲目隔离某个节点。
离线检查：`python3 -m unittest test_rotation_pool test_site_quality test_unified_quality`
与 `bash proxy-subscription.test.sh`。

每轮结束清理超过 48 小时且未被状态引用的统一模式报告、客户端日志和浏览器截图。
当前审批、失败记录及其引用的原始报告和截图始终保留；解析失败时跳过清理。

网站还会参考 Cookie、账号、访问行为和浏览器环境。通过检查代表当时该出口通过这些页面，
不承诺永久免验证，也不代表登录后的所有操作都已覆盖。服务器检测不包含用户电脑到入口的网络质量。
回滚先停 timer、等待 service 退出，在共享锁内恢复 `/root/deployment-backups/proxy-rotation-*`
或 `proxy-unified-*` 中的任务文件；Xray 恢复后先检查配置再重启。检测平台恢复为 DENY，
不要回退其他任务的文件或重新开放未经验证的全池。

## 2026-09-15 双站点预过滤

严格策略启用后，本节替代下文历史的全地区动态池与延迟优选策略。原订阅地址不变，
候选先经过两轮浏览器初筛，再通过两轮真实 Mihomo -> 公网 TLS -> Xray -> Resin
链路检查后才发布，每地区精确绑定一个固定上游。只通过 bridge 直测不能取得发布资格。
`Auto-Fast` 和 `Auto-Region` 保留名称，但改为固定顺序的 `fallback`，减少测速波动造成的出口切换。
本机直出和未通过审核的地区不再出现在已发布订阅中。客户端必须刷新订阅并重新选择 `Auto-Fast`。

检查目标是 `https://linux.do/` 和 `https://agentrouter.org/console/log`。
使用带界面的 Chromium、全新浏览器上下文，等待自动检查完成，不点击或拖动人机验证。
LINUX DO 必须显示真实话题链接；AgentRouter 必须显示真实登录入口。
后者仅代表未登录页面未触发滑块，不能证明登录后的个人日志页面、其他路径或用户浏览器永久免验证。
页面超过 18 秒才出现、验证码、未知页面和网络错误均不作为通过；12 秒以上另记慢加载。

旧 Resin SOCKS 日志的 `net_ok` 是传输指标，`http_status=0`；HTTP 200 的滑块页、
页面卡住和加载不全都可能被旧日志记为成功。因此不能把隧道失败比例当作用户页面失败率。
服务器测量也不包含客户端到公网入口的跨境延迟。

核心文件：

- `site-quality.py`：浏览器审计，记录页面分类、耗时、截图及前后出口 IP。
- `site_policy.py`：审批要求两轮非重叠客户端检查，绑定地区、node hash、端口、上游配置 hash、IP 和客户端实际选择；有效期 90 分钟。
- `site-control.py`：`discover`、`audit`、`seed`、`activate`、`enforce`、`refresh`、`revoke`、`quarantine`。激活前备份平台过滤器和原订阅。
- `verify-site-subscription.py`：逐地区启动隔离 Mihomo，使用真实订阅协议检查双站；`--auto-fast` 额外检查自动组实际选择。
- `site-subscription.py`：只发布有效且已有精确平台路由的地区；零有效出口时发布 `REJECT`，不会直连或重新开放全池。
- `proxy-rotation-quality.timer`：统一复测和续期入口，每轮结束后 3 分钟复测（另有 0–15 秒抖动）；发布和续期都必须再次通过两轮客户端检查。旧 `proxy-site-quality.timer` 已移除，不另启重复调度。
- 原 `proxy-region-latency.timer`：严格模式中只执行审批约束，禁用宽池回退。任务与节点池更新共享锁，忙时跳过，下一轮继续核对。

节点池每次重启新 bridge 前和回滚旧 bridge 前都会检查配置身份。被替换的固定端口先从
对应 `ProxyXX` 平台移除，避免相同 node hash/tag 指向未审核的新上游。只影响订阅专属平台，
不修改 AppsGlobal/AppsCN。上游自行轮换 IP 仍只能通过持续观测发现，不构成永久 IP 保证。

生产状态为 `/etc/xray/site-quality-policy.json` 与 `/var/lib/proxy-region-latency/site-approved.json`。
浏览器用独立 `proxy-site-browser` 用户运行，代码与固定 Chromium 位于 `/opt/proxy-site-quality/`，
只接收端口和非敏感身份信息，不能读取 Resin admin token 或 root 私有配置。
隔离 Mihomo 使用 `/opt/proxy-site-quality/mihomo`，凭据配置只写入 root 私有临时目录。
浏览器证据保存在 `/var/lib/proxy-site-browser/site-recheck-*/`，历史手工证据位于
`/var/lib/proxy-region-latency/site-audit-*/`，客户端合并报告为
`/var/lib/proxy-region-latency/client-round-*.json`，均不进入 Git。

客户端预检在数据锁内临时设置精确候选路由，先把旧审批作废并落盘，再运行检查，最后仅发布
两轮同时通过的地区。任何页面失败或进程异常都收回候选路由；systemd 的 `ExecStopPost`
也会重新约束路由并渲染订阅，避免超时后残留候选配置。初筛限时 300 秒，客户端阶段总限时 480 秒。
已发布订阅不用于存放预检配置，预检配置由同一生成器写入私有临时目录。

已有候选被删除、变为不健康或上游身份改变时，定时任务会为该地区寻找一个替补，排除旧出口 IP。
首次页面验证冷却 30 分钟，24 小时内重复验证或出口 IP 轮换隔离 24 小时；
临时网络、加载和未知页面错误需累计两轮失败才冷却 30 分钟。
隔离同时记录预期 IP 和实际观测到的 IP，保存在审批状态中，重新 `seed` 不会清空。
客户端预检和定时初筛会自动记录失败；手工审计报告用 `quarantine --report` 导入，
`verify-site-subscription.py` 复验失败也会立即隔离并撤下受影响出口。
浏览器超时会保留已发现的验证页证据，将未完成项记为失败，并清理该次浏览器进程组。
隔离同时清零旧审批，通过隔离冷却后仍需重新累计检查，旧审批不会自动恢复。
替补的通过次数从零开始，须跨两次定时任务通过初筛，再通过两轮客户端检查后才发布。
手工补充新地区仍须重新审计两轮并执行 `seed`；定时复测不会未经审核引入其他端口。
短期故障候选需重新积累两轮初筛，并通过两轮客户端检查；`revoke --region xx` 是持久撤销，
定时器不会自动重新启用，需重新审计并显式 `seed`。
审批全部失效时订阅可能暂时不可用，这是用户选择的严格过滤取舍。

```bash
python3 site-control.py discover --regions us,hk,sg
python3 site-control.py audit --report /path/round1/report.json
# 使用两轮新的完整报告，不可重复引用同一轮
python3 site-control.py seed --report /path/round1/report.json --report /path/round2/report.json
python3 site-control.py activate
python3 verify-site-subscription.py --auto-fast
systemctl enable --now proxy-site-quality.timer
systemctl start proxy-site-quality.service
python3 region-latency.py
```

回滚需先停止浏览器复测 timer、等待 service 结束并取得数据锁，移除严格策略文件，
从本次 `/root/deployment-backups/proxy-site-quality-*/platforms.json` 恢复平台的
`regex_filters`、`allocation_policy`，恢复同目录订阅快照；其余 Resin 平台和 Xray/Nginx 凭据无需改变。

本任务维护唯一的公网代理订阅。当前生产链路是：

```text
Mihomo/Clash
  -> TLS + HTTP/2 :443 (weesai.com)
  -> Nginx
       -> grpc_pass 127.0.0.1:12763 -> Xray VLESS/XHTTP stream-up（主）
       -> proxy_pass 127.0.0.1:12762 -> Xray VLESS/WebSocket（回退）
```

Xray 版本为 `26.3.27`。XHTTP 主节点用于减少 TLS/HTTP 升级和短连接重建，WS 节点继续保留，便于旧客户端或异常时快速回退。两种入站共享同一个 UUID，但使用不同的随机路径；TLS 只在 Nginx 终止，Xray 回环入站使用 `security: none`。

订阅在上述两个本机出口节点之外，为 Resin 中每个有健康出口的地区提供一个 `地区代码-Auto` 逻辑节点。`HK-Auto`、`JP-Auto`、`US-Auto` 保留原顺序，其余按地区代码排序。地区来自出口 IP 归属，不能根据节点名称猜测。每个地区拥有独立 VLESS/WebSocket 回环入站和 `Proxy地区代码` Resin 平台；现有端口保留，新增端口从 `13103` 开始选择 `13100`-`13999` 范围内未占用端口。境外地区使用 `managed-apps-public-pool`，`CN-Auto` 使用独立的 `managed-apps-cn-public-pool`。Account 为空，新建连接在区域健康池内动态选择，既有连接保持原出口。区域节点固定 `udp: false`。

地区清单和平台 ID 保存在 `/etc/xray/resin-region-platforms.json`。发现脚本分页读取所有健康节点并合并既有地区，避免某个地区短时掉线就消失或改变端口。订阅生成器和健康监控从实际 Xray 入站读取地区，不再写死地区名称或数量。新增来源地区后重新执行发现、配置和渲染命令即可加入；此任务没有新增自动重启生产服务的定时器。

`create-resin-region-platforms.sh` 幂等发现地区、创建并验收对应平台；`configure-region-nodes.sh` 幂等写入 Xray 入站/出站/路由和 Nginx 精确 location，密钥从 root-only 文件读取。回滚时恢复备份的 `proxy.json`、`proxy-ws.conf` 和平台清单，校验、重载服务并重渲染订阅；仅在确认不再被引用后才删除本批新建平台。

`configure-region-nodes.sh` 默认运行 check 模式：在临时目录组装候选配置，执行真实 `xray run -test` 和独立临时 Nginx 配置的 `nginx -t`，失败立即终止。`--apply` 在 `/root/deployment-backups/proxy-region-nodes-<时间戳>` 备份，安装后复验、重启 `xray-proxy`、reload `nginx`，确认所有地区端口监听后才返回。缺失项自动补全，重复 tag、错误端口等冲突直接拒绝。

`--apply` 在备份生成、安装生产文件前启用回滚 trap：此后任何步骤失败（含重启后监听与服务检查）都会自动从本次备份恢复 `proxy.json` 与 `proxy-ws.conf`，分别通过真实 `xray run -test` 与 `nginx -t` 后重启/重载，并返回非零。监听验收要求每个端口恰好一个监听且必须严格为 `127.0.0.1`，拒绝 `0.0.0.0`、`[::]` 等任何非 loopback 监听。

## 已落地的选择

- XHTTP 使用 `stream-up` 和 `alpn: [h2]`。Nginx 使用 `grpc_pass`、`grpc_read_timeout/grpc_send_timeout=3600s` 和 socket keepalive，适配长连接。
- XHTTP 不启用 H3、通用 `smux` 或手工 XMUX 参数；XHTTP 自带默认 XMUX，保留其随机连接轮换行为，避免撞上 Nginx 的请求数限制。
- WS 仅作为回退，不再作为订阅中的唯一节点。XHTTP 路径使用前缀匹配，允许其附加会话 ID。
- Xray `access` 日志关闭；Nginx XHTTP 日志只保留状态、字节数、耗时和上游信息，并使用 `buffer=32k flush=1s`，避免高频磁盘写入。
- 生成器在写文件前校验 WS/XHTTP 的 UUID、网络类型、TLS 终止模式、`stream-up`、端口和随机路径，防止 Xray 与 Nginx/订阅漂移。

## 客户端要求

建议使用 Mihomo `1.19.30` 或更新版本，然后刷新订阅。Clash Verge Rev `2.5.2` 通常内置 Mihomo `1.19.29`；该版本有公开的 XHTTP 长时间运行 CPU 占满报告，不能作为长期生产基线。刷新后应看到 `weesai.com-vless-443`（XHTTP）排在 `weesai.com-vless-443-ws`（回退）之前。

Mihomo 的 XHTTP `stream-up` 延迟探测在部分版本/网络上可能误报超时。XHTTP 主节点保留手动选择，不放入 `Auto-Fast`，避免 URLTest 误报影响自动组。若客户端 CPU 异常或真实流量断开，先手动选择 WS 回退并保留现场数据。

## 自动优选

刷新原订阅后，`PROXY` 首项为 `Auto-Fast`。已有客户端会通过 `store-selected` 保留上次选择，需手动切到 `Auto-Fast` 一次；不改变原订阅 URL、41 个代理条目、UUID、路径、地区名称或全量代理规则。

- `Auto-Fast`：仅包含现有 US/CA/JP/HK/SG/DE/NL 的 WS 地区节点，由客户端实测选择。`weesai.com-vless-443` 和 `weesai.com-vless-443-ws` 均保留在 `PROXY` 中手动选择。若没有符合条件的地区节点，生成器拒绝覆盖现有订阅。
- `Auto-Region`：所有地区节点的客户端测速组，需要公共池出口时使用。指定国家仍手动选择 `XX-Auto`，自动组不保证固定国家。
- 两组均每 300 秒测速，超时 5 秒、切换容差 100 ms、按需启用。测速地址只能代表该目标，不能保证所有网站或带宽都同样快。

`proxy-region-latency.timer` 在每轮结束后 5 分钟触发地区出口优选。每地区最多探测 16 个独立出口，优先参考延迟，并保留最多 4 个探索位；最多选入 8 个经过近期验证的出口。Global 只探测已校验的本机固定 SOCKS 槽位，使用 Cloudflare/Microsoft/Wikipedia 三站，三站全通过优先，至少两站通过才可入选；trace 明确显示其他地区的出口被排除。CN 仍使用 Resin 原生探测。候选故障、熔断或来源不符时不入选。

优选只修改清单中的 `ProxyXX` 专属平台，使用来源 MUST 加精确标签 OR 过滤和 `PREFER_LOW_LATENCY`；不修改 AppsGlobal/AppsCN。没有可用优选时回到该地区原池，并排除本轮明确地区不符的出口，绝不跨地区借用出口。无健康出口的地区可能暂时不可用，名称保留等待恢复。新物理节点会随池更新进入后续探测，无需重新发订阅；全新地区的入站配置仍按前述发现/配置流程管理。

两种后台任务共享数据面锁。小时更新先持有 `.priority` 排队锁，最多等待 780 秒；优选见到已排队更新就跳过，不能再令小时更新以成功状态静默跳过。优选探测软截止 300 秒，systemd 单轮上限 12 分钟。

部署优选单元：

```bash
install -m 0644 systemd/proxy-region-latency.service /etc/systemd/system/
install -m 0644 systemd/proxy-region-latency.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now proxy-region-latency.timer
```

首次原平台过滤器快照保存到 `/var/lib/proxy-region-latency/original-platforms.json`，不会每轮覆盖。回退时先停止优选 timer，等待运行中的优选自然结束，再运行 `python3 region-latency.py --restore`；原订阅文件快照位于本次 root-only 部署备份。`configure-region-nodes.sh` 保持 WS 协议，新旧配置相同不会重启服务；禁止原地迁移已发布的 WS 入站到 XHTTP。

`benchmark-proxy.py` 测实际公网 TLS/Xray 链路的多站首字节与失败数；`verify-mihomo.py --runtime-dir <隔离测试目录>` 使用该目录内的 Mihomo 和 `sub/` 候选订阅，验证自动组和 WS/XHTTP 实际流量。二者属于显式真实网络验收，不在离线单测或定时器里运行。服务器测值不等于大陆客户端 RTT。

### 2026-09-14 发布验收

- 公网原订阅 HTTP 200，内容与已发布文件一致；与发布前相比，41 个代理对象和规则完全一致，只增加选择组。
- 最新实际 Mihomo 测试中 Auto-Fast 12/12 成功，首字节中位数约 100 ms；同轮 XHTTP 3/3、手选 WS 2/3，失败发生在 Microsoft 超时。因此不能声称所有链路零故障。
- 同样 8 节点、三目标、每节点 12 次、无失败重试的基线为 9/96 失败，最终轮为 4/96。测试时段不同，不能据此保证固定提速比例；最终地区首字节中位数 HK 887、JP 798、US 175、DE 760、NL 541、SG 866 ms，也不是所有地区都比基线更快。
- HK/JP/US/CA/DE/KR/NL/SG 各两个出口样本均符合地区，部分地区取得不同出口，确认逻辑地区节点保持动态选择。
- 01:08 时 39 个地区平台中 36 个有路由，IE/MX/RU 暂无合格出口，名称保留。该状态会随公共源健康变化。
- 节点维护在 01:04 完整成功，优选在 01:08 完整成功。维护累计 CPU 106 秒，前一轮成功旧配置为 454 秒；本轮墙钟约 23 分钟，低并发用更长后台等待换取更低 CPU 竞争。不是客户端带宽或大陆 RTT 的测量。
- 本轮回滚资产：`/root/deployment-backups/proxy-optimization.h8ILZx/` 与原始地区平台快照；临时 Mihomo、其数据库和候选订阅在验收后删除，可按已验证版本重新准备。

订阅默认保留 `mode: rule` + `MATCH,PROXY`，这是有意的全量代理语义，不能在生成器里悄悄改成国内直连。若用户更重视国内网站延迟，应在客户端覆写中单独加入 CN/私网 `DIRECT` 规则；这会改变隐私和出口语义，须单独验收。

## 服务器限制和预期

当前主机约为 2 vCPU、3.6 GiB 内存，公网出口解析到美国 Santa Clara；从中国网络到该入口的 RTT 约 160--280 ms，晚高峰丢包或跨境路径波动无法靠订阅字段消除。XHTTP 主要减少握手和连接 churn，不会把物理 RTT 变成本地延迟。

BBR + `fq`、Nginx 443 backlog 4096、代理连接上限和握手突发阈值已经按现网证据调整。不要为了追求更低数字继续全局修改 `tcp_notsent_lowat`、服务端 TCP Fast Open、MTU probing 或无限复用；这些都应在独立 A/B 窗口中验证。宿主机 TCP 重传/超时和 swap 指标是全机参考，不能单独归因于代理。

## 文件和权限

脚本从以下 root-only 文件读取运行配置：

- `/etc/xray/proxy.json`
- `/etc/xray/subscription-token`

成功后原子更新：

- `/var/lib/proxy-subscription/<token>.yaml`（`root:www-data`、`0640`）
- `/root/proxy-subscription-url.txt`（`root:root`、`0600`）

密钥、UUID、token、完整路径和运行状态不进入 Git。仓库只保存脚本、测试和脱敏文档。

`examples/` 保存可恢复的脱敏结构：

- `examples/xray-proxy.json.example`
- `examples/nginx/proxy-security.conf.example`
- `examples/nginx/proxy-ws.conf.example`
- `examples/nginx/proxy-xhttp.conf.example`
- `examples/nginx/proxy-subscription.conf.example`

示例中的 HK/JP/US 仅展示结构，不是允许地区的限制。部署脚本为每个新增地区生成独立随机路径；现有 UUID 和路径保持稳定。XHTTP location 必须保留路径末尾的 `/` 前缀匹配，并放在启用 `ssl http2` 的站点内。示例不是生产密钥来源，禁止把替换后的文件提交回仓库。

## 生成和部署

```bash
cd /opt/resin-operations/operations/tasks/proxy-subscription
bash -n render-proxy-subscription.sh
jq empty examples/xray-proxy.json.example
./create-resin-region-platforms.sh
./configure-region-nodes.sh --check
./configure-region-nodes.sh --apply
./render-proxy-subscription.sh

# 只校验配置，不发起真实代理拨号
/usr/local/lib/xray/v26.3.27/xray run -test -config /etc/xray/proxy.json
nginx -t
systemctl is-active nginx xray-proxy
```

生成器失败时不会替换现有订阅文件。修改 Xray UUID、路径或端口后，必须先通过 `xray run -test`、`nginx -t`，再重新生成并刷新客户端；不要手工在订阅里复制敏感字段。

`bash proxy-subscription.test.sh` 使用临时 fixture 和 PyYAML 做离线验证：超过三个地区的完整渲染、旧节点字段、排序、订阅地址稳定性，以及错误路由、粘性账号、重复端口或错误凭据时拒绝覆盖现有订阅。

`python3 verify-region-nodes.py` 是显式执行的公网端到端验收，不属于离线测试或定时任务。默认每个节点取得两个成功样本，支持 `--regions sg,de` 定向检查。临时客户端配置经 stdin 传给 Xray，退出时关闭客户端，只输出地区和计数。地区采用 Resin 同样优先使用的在线 trace `loc`；本机 Meta MMDB 有时返回注册地或 `google`、`cloudflare` 标签，仅作为差异记录，不能据此判定转发区域错误。

## 回滚

1. 客户端先选择 `weesai.com-vless-443-ws`，确认真实流量恢复。
2. 保留 XHTTP 日志和健康指标，不要通过删除日志掩盖失败。
3. 若需服务端回滚，恢复已核验的 Xray/Nginx 配置快照，分别执行 `xray run -test`、`nginx -t`，再按现网维护流程平滑重载。
4. WS 入站和订阅回退节点在观察期内不得删除；XHTTP 只在连续观测稳定后才可考虑单独调整。

## 监控和判读

`tasks/xray-proxy-health/` 每分钟记录：服务和监听状态、WS `101/503/429`、XHTTP `2xx/499/其他`、连接数、TLS 探针、Nginx 限流事件、内存/swap 和主机 TCP 增量计数。`xhttp` 的 `upstream_connect` 接近 0 只说明 Nginx 到本机 Xray 没有排队，不代表公网到客户端的 RTT 已消失。URLTest 超时也不能代替真实流量判定。

## 参考资料

- [Xray XHTTP 官方讨论](https://github.com/XTLS/Xray-core/discussions/4113)
- [Xray 日志配置](https://xtls.github.io/config/log.html)
- [Mihomo 配置示例](https://github.com/MetaCubeX/mihomo/blob/v1.19.30/docs/config.yaml)
- [Mihomo v1.19.30](https://github.com/MetaCubeX/mihomo/releases/tag/v1.19.30)
- [Mihomo XHTTP 长时间 CPU issue #3047](https://github.com/MetaCubeX/mihomo/issues/3047)
- [Mihomo stream-up 延迟探测 issue #2772](https://github.com/MetaCubeX/mihomo/issues/2772)
- [Nginx gRPC 模块](https://nginx.org/en/docs/http/ngx_http_grpc_module.html)
- [Nginx access_log 缓冲](https://nginx.org/en/docs/http/ngx_http_log_module.html#access_log)

独立公开仓库不适合承载这套生产订阅：即使脚本不硬编码密钥，域名、路径格式和运维上下文也容易被误提交。当前模块纳入现有私有 `WesPerez/server-scheduled-tasks` 仓库，足够保存经验并便于回滚。
