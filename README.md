# prism-node

自研节点：AnyTLS 服务端（Rust）。配置文件沿用 sing-box 格式，[sbm](https://github.com/yuuolo/sbm) 现有的节点配置可以直接使用；[Prism](https://github.com/yuuolo/prism)、sing-box、mihomo（Clash Meta）客户端都能连接。

```bash
cargo build --release      # 产物：target/release/prism-node
```

和 sing-box 节点相比：

- **热加载**：改配置后执行 `systemctl reload prism-node`（即 SIGHUP）或 `prism-node reload`，用户、证书、padding 方案、fallback 即时生效，已有连接不断；被删除或改了密码的用户会立即断开
- **按用户统计流量**：内置计数，`prism-node stats` 输出 JSON，不再需要 iptables 标记
- **防主动探测**：认证失败的连接可以转给一个伪装站点（`fallback`）
- **默认禁止访问节点本机**：回环、链路本地（含云厂商元数据地址 169.254.169.254）和未指定地址默认拒绝，用户无法通过代理访问节点上的控制 API

## 配置

只读取 `type: anytls` 的入站，其余入站会跳过并给出警告。`outbounds` 和 `route` 会被忽略（流量统计已经内置）。

```json
{
  "log": {"level": "info"},
  "inbounds": [{
    "type": "anytls", "tag": "anytls-in", "listen": "::", "listen_port": 443,
    "users": [{"name": "u001", "password": "..."}],
    "padding_scheme": [],
    "tls": {"enabled": true, "server_name": "n1.example.com",
            "certificate_path": "/etc/letsencrypt/live/n1.example.com/fullchain.pem",
            "key_path": "/etc/letsencrypt/live/n1.example.com/privkey.pem"},
    "fallback": {"server": "127.0.0.1", "server_port": 8080}
  }],
  "api": {"listen": "127.0.0.1:9550"},
  "allow_local": false
}
```

| 字段 | 说明 |
|---|---|
| `padding_scheme` | 同 sing-box，每行一项；留空时使用 anytls 默认方案。客户端方案不一致时，服务端会把这里的方案下发给客户端 |
| `tls.certificate` / `tls.key` | 也可以直接写入 PEM 内容（字符串或按行的数组），代替 `*_path` |
| `fallback`（扩展） | 认证失败时把连接（TLS 解密后的明文）转发到这里 |
| `api.listen`（扩展） | 本地控制 API，默认 `127.0.0.1:9550`；设为空字符串则关闭 |
| `allow_local`（扩展） | 设为 `true` 时允许访问本机地址，默认 `false` |

`listen` 为 `::` 时同时监听 IPv4 和 IPv6。改 `listen` / `listen_port` / `api` 或增删入站需要重启，其余改动 reload 即可生效。

## 命令行

```bash
prism-node -c /etc/prism-node/config.json            # 运行（等同 run）
prism-node check -c /etc/prism-node/config.json      # 检查配置
prism-node stats                                     # 各用户累计流量（JSON）
prism-node reload                                    # 重新读取配置（同 SIGHUP）
prism-node version
```

`stats` 输出示例。计数从进程启动起累计、reload 后保留，重启后归零（读取方按「新值小于旧值即视为重启」计算增量）。还没有产生过连接的用户不会出现在列表里。

```json
{"version":"0.1.7","uptime":3600,"sessions":3,
 "users":{"u001":{"up":1048576,"down":52428800,"sessions":2}}}
```

## systemd

```ini
[Unit]
Description=prism-node
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/prism-node run -c /etc/prism-node/config.json
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
```

## 测试

```bash
cargo test                                     # 单元测试 + 与 Prism 客户端的回环互通
PRISM_E2E_SINGBOX=/path/to/sing-box PRISM_E2E_MIHOMO=/path/to/mihomo \
  cargo test --test clients -- --nocapture       # 与 sing-box / mihomo 客户端互通
```
