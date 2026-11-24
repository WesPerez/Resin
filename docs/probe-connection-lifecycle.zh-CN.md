# 探测超时后的连接回收

2026-09-30 审计发现，宿主 bridge 的旧 generation 长期存在只返回 SOCKS
握手应答（12 字节）、收到约 1.5 KiB 后数小时无数据的连接。按 HAProxy
会话、socket inode 和反向端口核对，其中一批客户端属于 Resin。它们使旧代
无法排空；每小时发布与最多四代的限制叠加，造成 Global 刷新长期 deferred。
不能只按 ESTABLISHED/CLOSE_WAIT 判断业务是否仍在使用连接。

Go 1.25 的 `net/http.Transport.getConn` 使用 `context.WithoutCancel`，允许
共用连接池在请求取消后继续建连，供未来请求复用。请求超时返回不代表底层
TCP/TLS 已结束；手工创建 Transport 的 `TLSHandshakeTimeout` 默认为零。
`DisableKeepAlives` 也不回收仍在等待 TLS 的连接。

`HTTPGetViaOutbound` 每次请求独享 Transport，因此在函数返回时调用
`CloseIdleConnections`：成功时先关闭响应体，失败时也取消已经无人等待的
建连及握手。原请求 context 继续决定探测总时限。共用的代理 Transport 和
DirectFetcher 则使用 30 秒建连、10 秒 TLS 握手时限；这两个时限只约束连接
建立阶段，不给已经建立的 CONNECT/WebSocket/SSE 会话设总时长。

回归测试使用本地不返回 TLS 响应的端点，分别验证专用探测取消后 socket
关闭、pending dial 的 context 取消，以及共用连接池中的遗留 TLS 握手有界
结束。CI 同时对 netutil/probe 执行 race 检查，不访问生产节点。

上线使用现有 Resin 蓝绿部署。新进程防止继续产生该类残留；旧进程已有的
连接不会因为替换镜像而获得新逻辑，需按既有排空流程退出。bridge 的四代
保护继续保留：正常长连接仍可能阻止某次更新，本修复不承诺任意长连接下
永不等待，也不以强制终止在途业务制造容量。
