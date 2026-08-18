# Packy 用量中心

一个本地运行、可部署到 NAS 的 PackyAPI 用量查询服务。

- `/my` 按来源 IP 显示当前用户有权查看的账号。
- `/leaderboard` 只公开主动参与排行的账号名称和已用金额。
- 同一个 Key 可以绑定多个 IP，同一个 IP 也可以绑定多个 Key。
- Key 使用 AES-256-GCM 加密保存在 SQLite 中，不会下发到浏览器。
- 私有页与排行榜共用每账号至少 120 秒的服务端缓存。

## 本地运行

需要 Node.js 24 或更高版本：

```sh
node packy-usage-server.mjs
```

Windows 也可以直接运行 `start-packy-usage.cmd`。

打开：

- `http://127.0.0.1:8765/my`
- `http://127.0.0.1:8765/leaderboard`

首次启动会在 `data` 目录生成 SQLite 数据库和本地主密钥。`data`、主密钥、API Key 和旧账号配置都不应提交到 Git。

## 测试

```sh
node --test packy-usage-server.test.mjs
```

测试覆盖多 Key/多 IP、IP 隔离、排行榜字段过滤、120 秒缓存、并发请求合并、解绑删除、可信代理解析、HTTPS 限制和登记限流。

## NAS 部署

参见 [`NAS-DEPLOYMENT.md`](NAS-DEPLOYMENT.md) 和 `compose.example.yaml`。生产环境必须通过 HTTPS 反向代理访问，并将 `TRUSTED_PROXY_CIDRS` 限制为真实代理地址或子网。

## 安全提醒

- 不要提交 `data/`、`secrets/`、`.env` 或任何包含真实 Key 的文件。
- 不要将 `TRUSTED_PROXY_CIDRS` 设置为 `0.0.0.0/0` 或 `::/0`。
- 数据库和主密钥应分开备份；丢失主密钥后无法解密已保存的 Key。
