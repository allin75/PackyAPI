# packycode用量查询

一个本地运行、可部署到 NAS 的 PackyAPI 用量查询服务。

- `/my` 使用安全浏览器会话显示当前用户绑定的账号；首次使用需要输入一次 Packycode Key。
- `/leaderboard` 使用赛事转播式领奖台和紧凑榜单，显示相较上一轮 5 分钟周期的名次变化。
- 排行榜 API 只公开名称、已用金额、名次和变化状态，不公开账号 ID、Key、IP 或剩余额度。
- 排行榜逐个刷新账号以避免上游突发限流；刷新受限时保留上次有效快照并冷却 10 分钟后自动重试。
- 同一个浏览器会话可以绑定多个 Key；不同浏览器会话互相隔离，即使共用同一个出口 IP。
- 旧 IP 绑定记录会保留用于迁移和审计，但不再作为私有页面授权依据。
- Key 使用 AES-256-GCM 加密保存在 SQLite 中，不会下发到浏览器。
- 私有页与排行榜共用每账号至少 5 分钟的服务端缓存。

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

测试覆盖多 Key/多会话隔离、排行榜字段过滤、数据库迁移、名次升降、5 分钟持久化快照、并发请求合并、失败回退、会话解绑、可信代理解析、HTTPS 限制和登记限流。

## NAS 部署

参见 [`NAS-DEPLOYMENT.md`](NAS-DEPLOYMENT.md) 和 `compose.example.yaml`。生产环境必须通过 HTTPS 反向代理访问，并将 `TRUSTED_PROXY_CIDRS` 限制为真实代理地址或子网。

## 安全提醒

- 不要提交 `data/`、`secrets/`、`.env` 或任何包含真实 Key 的文件。
- 不要将 `TRUSTED_PROXY_CIDRS` 设置为 `0.0.0.0/0` 或 `::/0`。
- 数据库和主密钥应分开备份；丢失主密钥后无法解密已保存的 Key。
