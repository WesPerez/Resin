# 订阅转换器

宿主节点池维护使用的离线转换入口。通过 Resin 现有解析器读取 stdin 的 URI、Clash、
base64 或 sing-box 订阅，只向 stdout 输出 `outbounds`；输入上限为 16 MiB。
失败返回非零状态，不回显可能包含凭据的输入内容。

`Subscription Converter` GitHub-hosted workflow 运行该命令的测试并生成 Linux amd64
二进制、完整提交 `revision.txt` 和 `SHA256SUMS`。它不依赖 WebUI，也不部署服务。
生产机只安装经过完整提交与校验和核验的 CI 产物，安装目标为
`/opt/resin-subscription-converter/bin/subscription-converter`。

```sh
subscription-converter < input.txt > singbox.json
```

该转换器只解析格式；端点限制、协议兼容性和节点准入探测仍由宿主维护任务执行。
