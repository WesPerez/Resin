# xray-proxy-health

该任务每分钟采样公网 443 主代理入口的服务状态、TLS、监听、WS 101/503/短会话比例、XHTTP 2xx/499/错误、总并发/来源分布、443 与 Xray 回环后端的候选前置卡顿差值、内存、TCP 重传/超时和监听队列丢弃，写入本地 JSONL，并在异常时写 journald 与告警日志。它不使用订阅凭据发起真实 VLESS 拨号，不改变代理业务流量。

链路范围是：nginx:443 -> xray-proxy:12762（WS）及 12763（XHTTP）。本机应用出站由隔离 Resin 数据面负责，不在本任务中重复探测。

conn_443_est、peer_count_443_est 和 max_peer_443_est 是宿主机 nginx 公网 443 的总量，可能包含同端口的其他虚拟主机；conn_backend_est 合并统计 Xray 的 WS `12762` 和 XHTTP `12763` 回环连接，只计 `ss` 输出中 peer 为后端端口的一侧，避免把同一 loopback socket 算两次。WS access 与 XHTTP access 指标才是各自入口的专属证据。conn_443_backend_gap 只在差值与单 peer 并发同时越过阈值时标记 pre_ws_stall_candidate，仍不能脱离客户端时间戳直接写成“后端握手卡住”。

TCP 重传、SYN 重传、超时、swap 和内存 PSI 来自整台主机，可能被 Docker、数据库、构建或其他站点放大；它们只能作为相关性信号，不能单独证明代理链路故障。XHTTP `499` 表示客户端主动关闭，通常需要和客户端日志、持续时间及上游状态一起判读。

系统安装文件：

- /etc/systemd/system/xray-proxy-health.service
- /etc/systemd/system/xray-proxy-health.timer
- /etc/server-scheduled-tasks/xray-proxy-health.env
- /var/log/xray-proxy-health/metrics.jsonl
- /var/log/xray-proxy-health/alerts.log
- /var/lib/server-scheduled-tasks/xray-proxy-health/

Nginx 入口日志由 `/var/log/nginx/proxy-ws-access.log` 和 `/var/log/nginx/proxy-xhttp-access.log` 提供；XHTTP 日志使用缓冲格式且不记录完整随机路径。

service 通过 `SupplementaryGroups=adm` 读取 Nginx 的 `0640 www-data:adm` 日志，仍保持空 capability 集。采样同时读取当前日志和 `.1`，按 inode 去重，覆盖日志轮转边界；每文件最多读取末尾 8 MiB。schema 3 的 `log_sources` 独立标记 `ok`、`missing`、`unreadable`、`truncated` 或 `invalid_format`。缺测字段写 `null` 并告警，不当作零流量；范围截断同样不提供看似完整的计数。下游统计必须排除不完整来源，不能把 `null` 补零。

`subscription_metrics.py` 只读汇总独立的普通/严格池容量、客户端真实拨测、bridge 代数与 Global/CN 维护结果，并接入同一告警及恢复日志。split 模式下拨测超过 15 分钟未完成、池状态超过 30 分钟未更新均告警，缺测不补零；普通网络拨测失败为 critical，严格池与 CN 维护失败分别标记 warning。bridge 状态超过 120 秒、四代容量占满、维护结果超过三小时也会单独标记。只复制脱敏白名单字段，不复制凭据、出口 IP 或原始错误。

手工验证：

    systemctl start xray-proxy-health.service
    journalctl -u xray-proxy-health.service -n 20 --no-pager
    jq . /var/lib/server-scheduled-tasks/xray-proxy-health/last-status.json

告警阈值可通过 /etc/server-scheduled-tasks/xray-proxy-health.env 调整。任务只追加本地指标，日志由 /etc/logrotate.d/xray-proxy-health 按现有 14 天策略轮转。

任务不使用订阅 token，不执行真实 VLESS 拨号，也不把 URLTest 超时当作代理故障。当前 XHTTP 主节点的验收顺序是：先确认 `xhttp_total` 中错误比例、Nginx `upstream_connect`、Xray 服务状态，再结合客户端真实请求的首包延迟、CPU 和断流；不要只看单次 TLS 探针。主机资源异常应另行定位来源，不要通过重启 Xray 掩盖。

XHTTP 的设计和 Nginx `grpc_pass` 依据见 [proxy-subscription README](../proxy-subscription/README.md)；客户端建议使用 Mihomo `1.19.30` 或更新版本。

## 区域节点监听

健康采样通过 `REGION_BACKEND_PORTS=auto` 从 `/etc/xray/proxy.json` 的 `proxy-ws-地区代码` 入站读取全部地区端口，逐端口输出到 `region_listeners`，任一端口缺失触发 `region_listeners_missing` 告警；`conn_backend_est` 也计入全部地区。可显式设置带引号的端口列表用于特殊部署。这些是服务器本机入口存活指标，区域出口仍需 Resin/公网拨测单独验收。
