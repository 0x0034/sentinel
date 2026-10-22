# Sentinel

使用 Go **1.27.2** 编写的 RSS → 飞书通知服务。每 5 分钟发现新公告，每天北京时间 09:00 发送昨日汇总；两种通知都使用红色标题卡片。支持多组订阅，SQLite 保存公告、基线、去重和待发送任务。

**当前来源限制：** `https://rsshub.app/aliyun/notice/2` 在 2026-10-22 实测返回 HTTP 403。生产运行前，请将配置中的 URL 换为可访问的同一路由，例如自有 RSSHub 实例；服务不会自动切换到其他来源。该路由是阿里云安全公告，最多返回最新 12 条，汇总只能覆盖已经采集到的数据。

## 使用 Docker

镜像：`registry.cn-hangzhou.aliyuncs.com/0x0034/sentinel:0.1.0`，平台为 `linux/amd64`。

1. 复制示例并编辑 RSS 地址：

   ```sh
   cp config.example.yaml config.yaml
   ```

2. 通过现有凭证存储或终端环境设置 `FEISHU_WEBHOOK_URL`。配置文件只保存变量名，不保存 webhook 值；不要把真实值提交到 Git。

3. 验证配置并启动：

   ```sh
   docker compose run --rm sentinel check -config /etc/sentinel/config.yaml
   docker compose up -d
   docker compose logs -f sentinel
   ```

`sentinel-data` 命名卷保存 `/data/sentinel.db`。容器以 UID/GID `65532` 运行，根文件系统只读；自定义绑定数据目录时，应确保该用户可写。单份数据库只支持一个进程，重复启动会报错退出。

仅有一份 amd64 镜像；ARM 主机需要容器平台提供 amd64 模拟支持。

## 配置

见 [config.example.yaml](config.example.yaml)。`incremental` 和 `digest` 必须显式设置，至少启用一个；配置字段拼错、缺失凭证或不合法时间会在启动时失败。

| 字段 | 说明 |
| --- | --- |
| `database` | SQLite 文件路径，默认 `/data/sentinel.db` |
| `poll_interval` | 抓取间隔，默认 `5m`，范围 `1s` 至 `24h` |
| `timezone` | 日期边界时区，默认 `Asia/Shanghai` |
| `digest_time` | 每天汇总时间，默认 `09:00` |
| `subscriptions[].id` | 稳定订阅 ID，隔离基线、公告和任务 |
| `subscriptions[].url` | RSS/Atom URL，可使用 HTTP 自建源或 HTTPS |
| `subscriptions[].webhook_env` | 飞书 webhook 对应的环境变量名 |
| `subscriptions[].incremental` | 是否为新公告产生增量任务 |
| `subscriptions[].digest` | 是否产生昨日汇总任务 |

增加订阅时复制配置条目并使用唯一 ID；不同机器人使用不同的环境变量名，并在 Compose 中转交这些变量。服务不热加载配置，修改后重启。迁移同一个来源的访问地址可保留 ID；换成不同来源时应使用新 ID。移除订阅后，其待发送任务保留但暂停发送，重新添加同一 ID 后继续。

目前支持无需额外签名的飞书自定义机器人 webhook。若机器人配置了 IP 白名单或关键词限制，需要让运行环境和卡片内容符合其设置；服务会将非零业务响应作为失败重试。需要签名的机器人需要先扩展配置与签名支持。

## 通知规则

- 首次成功抓取建立基线，保存但不补推历史增量；失败请求不会建立基线。
- 新发现的公告产生增量通知。GUID 优先作为身份，缺失时使用原文链接；两者都没有的条目跳过。已有公告的内容修改只更新保存记录。
- 昨日汇总按发布时间和配置时区筛选前一个自然日，包含基线公告。没有发布时间的公告不进入日期汇总。
- 09:00 后恢复时，仅补生成昨天的汇总；更早已经生成的失败任务仍会重试。
- 空日发送“未采集到昨日公告”。抓取失败会在汇总中标明，避免误报为平台没有发布内容。
- 汇总生成后内容固定，按请求体大小拆分，每张卡片小于 18 KiB；迟到公告不重做已生成的汇总。
- 发送失败从 30 秒开始指数退避，最长间隔 30 分钟，不自动丢弃任务。共享机器人合并节流，每秒最多发送一次。
- 只有 HTTP 成功且 JSON `code: 0` 才确认成功。响应丢失或发送成功后进程崩溃可能造成少量重复；不提供严格恰好一次保证。
- 历史公告与任务首版不自动删除，需保留数据卷并按运行规模安排备份和磁盘监控。

## 命令

```sh
sentinel run -config config.yaml       # 常驻服务（默认命令）
sentinel once -config config.yaml      # 抓取、生成到期汇总并处理本轮最多 100 个到期任务
sentinel check -config config.yaml     # 本地配置与凭证格式检查，不发送消息
sentinel send-test -config config.yaml # 每个配置订阅发送两张明确标识的测试卡片
sentinel version                      # 应用版本、Go 编译版本和目标平台
```

`send-test` 会真实发送消息，但不读写 SQLite，也不改变生产基线。它测试机器人连通性，不代表真实 RSS 地址可用。`once` 在 RSS 失败时返回非零退出码，发送失败则保存重试任务；持续重试需要运行常驻服务。

## 开发与构建

```sh
make check test build
bin/sentinel version
make image
```

Makefile 固定 `GOTOOLCHAIN=go1.27.2`。Docker 构建使用 `registry.cn-hangzhou.aliyuncs.com/0x0034/golang:1.27` 并固定 digest；该标签当前内置 Go 1.27.3，因此构建阶段显式下载、使用和校验 Go 1.27.2 工具链。纯 Go SQLite 驱动支持 `CGO_ENABLED=0` 的 amd64 构建。`make image` 构建并加载镜像；`make push` 将 `0.1.0` 和 `latest` 推送到配置的仓库。

运行基础镜像使用 `registry.cn-hangzhou.aliyuncs.com/0x0034/alpine:3.22` 并固定 digest。APK 软件源使用 `https://mirrors.aliyun.com/alpine/`，在安装 TLS 证书前完成替换。

构建时 `GOPROXY` 默认使用 `https://goproxy.cn,direct`，保持 Go 默认校验机制。可用 `docker buildx build --build-arg GOPROXY=...` 按环境覆盖。

测试使用临时 SQLite、RSS 样例与本地 HTTP 服务，不调用真实机器人。覆盖跨时区日期边界、基线与增量、修改去重、故障和重启恢复、分片、业务响应与共享目标节流。

设计见 [实施方案](docs/design/rss-feishu.md)、[领域词汇](GLOSSARY.md) 和 [投递决策](docs/adr/0001-durable-notification-delivery.md)。本次测试结果、镜像 digest 与来源限制见 [0.1.0 验收记录](docs/verification/2026-10-22.md)。
