# Packy 用量中心 NAS 部署

## 1. 准备主密钥

在 `outputs` 目录下创建 `secrets` 目录，并生成仅供该服务使用的 32 字节主密钥：

```sh
mkdir -p secrets
node -e "process.stdout.write(require('node:crypto').randomBytes(32).toString('base64'))" > secrets/master.key
chmod 600 secrets/master.key
```

主密钥用于解密 SQLite 中的 PackyAPI Key。备份时必须同时保存 `data` 目录和 `secrets/master.key`，但应将两者分开保管。

## 2. 启动容器

将示例文件复制为 Compose 配置并启动：

```sh
cp compose.example.yaml compose.yaml
docker compose up -d --build
docker compose ps
```

默认只在 NAS 主机的 `127.0.0.1:8765` 上开放端口，不能从局域网直接绕过 HTTPS 反向代理访问。

## 3. 配置 HTTPS 反向代理

NAS 自带 Nginx 或 Nginx Proxy Manager 的上游地址设为 `http://127.0.0.1:8765`，并传递原始主机、协议和来源 IP：

```nginx
location / {
    proxy_pass http://127.0.0.1:8765;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}
```

`TRUSTED_PROXY_CIDRS` 必须覆盖反向代理连接到容器时使用的地址。示例默认信任 Docker 私网 `172.16.0.0/12`；确认实际代理地址后应缩小到具体 IP 或子网。不要配置成 `0.0.0.0/0` 或 `::/0`。

如果 Nginx Proxy Manager 也运行在 Docker 中，可将两个服务加入同一自定义网络，取消 `ports`，并将上游设为 `http://packy-usage:8765`；同时把该网络的实际子网写入 `TRUSTED_PROXY_CIDRS`。

## 4. 验证

通过最终 HTTPS 域名检查：

```text
https://your-domain.example/my
https://your-domain.example/leaderboard
https://your-domain.example/health
```

在两个不同浏览器会话中输入同一个 Key，应识别为同一个账号；同一出口 IP 下的不同浏览器不应互相看到账号或余额。排行榜只应返回账号名称、已用金额、名次和变化状态，不应包含账号 ID、Key、IP 或剩余额度。

## 5. 备份和升级

- 备份前停止容器，再备份整个 `data` 目录和单独保存的主密钥。
- 丢失主密钥后，数据库中的 Key 无法恢复。
- 更新文件后运行 `docker compose up -d --build`。
- 新服务验证完成后，再安全删除旧的 `packy-accounts.json` 明文配置。
