# Sentinel

使用 Go **1.27.2** 编写的 RSS / 阿里云高风险漏洞库 → 飞书通知服务。每 5 分钟检查新条目，每天北京时间 09:00 发送昨日汇总，均使用红色标题卡片。支持多组订阅，SQLite 保存基线、去重和待发送任务。

**当前来源限制：** `https://rsshub.app/aliyun/notice/2` 在 2026-10-22 实测返回 HTTP 403。生产运行前，请将配置中的 URL 换为可访问的同一路由，例如自有 RSSHub 实例；服务不会自动切换到其他来源。该路由是阿里云安全公告，最多返回最新 12 条，汇总只能覆盖已经采集到的数据。

## 使用 Docker

候选镜像：`registry.cn-hangzhou.aliyuncs.com/0x0034/sentinel:0.2.0-rc.3`，平台为 `linux/amd64`。包含 Chromium 运行依赖；正式版本 `latest` 仍保持原版本。

1. 复制示例，保留需要的订阅并编辑 RSS 地址（仅使用漏洞库时可删除 RSS 条目）：

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

`sentinel-data` 命名卷保存 `/data/sentinel.db`。容器以 UID/GID `65532` 运行，根文件系统只读，`/tmp` 提供 Chromium 临时配置和缓存空间，`init: true` 负责回收子进程。自定义绑定数据目录时，应确保该用户可写。单份数据库只支持一个进程，重复启动会报错退出。

示例配置显式设置 `browser.no_sandbox: true`，因为当前容器平台配合 `no-new-privileges` 不支持 Chromium 自身的 namespace sandbox；浏览器隔离依靠非 root 容器、只读根文件系统和移除全部 capabilities。具备 Chromium sandbox 支持的主机应将此项改为 `false`，配置缺省值也是 `false`。

仅有一份 amd64 镜像；ARM 主机需要容器平台提供 amd64 模拟支持。

## 配置

见 [config.example.yaml](config.example.yaml)。`incremental` 和 `digest` 必须显式设置，至少启用一个；配置字段拼错、缺失凭证或不合法时间会在启动时失败。

| 字段 | 说明 |
| --- | --- |
| `database` | SQLite 文件路径，默认 `/data/sentinel.db` |
| `poll_interval` | 抓取间隔，默认 `5m`，范围 `1s` 至 `24h` |
| `timezone` | 日期边界时区，默认 `Asia/Shanghai` |
| `digest_time` | 每天汇总时间，默认 `09:00` |
| `browser.executable` | 可选 Chromium 可执行文件；默认搜索系统安装，macOS 支持标准 Chrome 路径 |
| `browser.page_timeout` | 单页总时限，默认 `45s`，范围 `1s` 至 `2m` |
| `browser.no_sandbox` | 默认 `false`；仅在容器平台无法提供 Chromium sandbox 时显式启用 |
| `subscriptions[].id` | 稳定订阅 ID，隔离基线、公告和任务 |
| `subscriptions[].type` | 默认 `rss`；`aliyun_high_risk` 采集高风险列表，`aliyun_cve` 兼容原 CVE 列表，均使用 Chromium |
| `subscriptions[].url` | RSS/Atom URL；高风险来源固定为 `https://avd.aliyun.com/high-risk/list`，CVE 来源固定为 `https://avd.aliyun.com/nvd/list`，省略时按类型填充 |
| `subscriptions[].pages` | 漏洞库来源默认前 5 页，范围 `1` 至 `20`；RSS 不支持此字段 |
| `subscriptions[].webhook_env` | 飞书 webhook 对应的环境变量名 |
| `subscriptions[].incremental` | 是否为新公告产生增量任务 |
| `subscriptions[].digest` | 是否产生昨日汇总任务 |

增加订阅时复制配置条目并使用唯一 ID；不同机器人使用不同的环境变量名，并在 Compose 中转交这些变量。服务不热加载配置，修改后重启。迁移同一个 RSS 来源的访问地址可保留 ID；切换来源类型必须使用新 ID，否则服务报错。移除订阅后，其待发送任务保留但暂停发送，重新添加同一 ID 后继续。

切换原 CVE 订阅时，使用示例中的 `id: aliyun-high-risk`、`type: aliyun_high_risk` 和高风险 URL，移除原 `aliyun-cve` 条目后重启。新订阅首次成功扫描会静默建立独立基线，避免把窗口中的历史记录批量推送；原订阅的历史记录保留。

旧配置缺省保持 RSS 行为。升级前停止服务并备份 SQLite 数据及其 WAL 文件；启动会将数据库迁移为版本 2，保留 RSS 记录和待发送消息。旧版程序不能打开升级后的数据库，回滚需恢复备份。

目前支持无需额外签名的飞书自定义机器人 webhook。若机器人配置了 IP 白名单或关键词限制，需要让运行环境和卡片内容符合其设置；服务会将非零业务响应作为失败重试。需要签名的机器人需要先扩展配置与签名支持。

## 通知规则

- 首次成功抓取建立基线，保存但不补推历史增量；失败请求不会建立基线。
- 新条目产生增量通知。RSS 使用 GUID 或原文链接去重；漏洞库来源使用详情链接中的 AVD 标识，CVE 编号作为展示字段。已有条目内容变化只更新记录，不再次发送。
- RSS 昨日汇总按公告发布时间筛选，包含基线公告；没有发布时间的公告不进入汇总。漏洞库使用“昨日新发现”，按 Sentinel 首次成功保存时间统计，排除初始化基线，来源披露日期单独显示。
- 09:00 后恢复时，仅补生成昨天的汇总；更早已经生成的失败任务仍会重试。
- 空日仍发送汇总，RSS 显示“未采集到昨日公告”，漏洞库显示“未发现昨日新增漏洞记录”。抓取失败会注明，避免误报为平台没有发布内容。
- 汇总生成后内容固定，按请求体大小拆分，每张卡片小于 18 KiB；迟到公告不重做已生成的汇总。
- 发送失败从 30 秒开始指数退避，最长间隔 30 分钟，不自动丢弃任务。共享机器人合并节流，每秒最多发送一次。
- 只有 HTTP 成功且 JSON `code: 0` 才确认成功。响应丢失或发送成功后进程崩溃可能造成少量重复；不提供严格恰好一次保证。
- 历史公告与任务首版不自动删除，需保留数据卷并按运行规模安排备份和磁盘监控。

## 漏洞库来源范围

默认完整扫描前 5 页，当前每页 30 条，约覆盖 150 条。任一页面失败、挑战页、页码错位、整页重复或同一 AVD 内容冲突都会使本轮采集失败，下一轮重新扫描；只有完整成功才保存条目及发送任务。高风险列表实测存在相邻页的相同条目重复，按 AVD 去重后保存一次；原 CVE 列表继续严格拒绝跨页重叠。不会在遇到已见条目或旧披露日期时提前停止，也不保证全库覆盖、旧条目持续更新或任意停机时长后的补齐。修改页数会改变监测窗口，新进入窗口的旧条目也会被视为首次发现。

默认监测阿里云高风险列表 `https://avd.aliyun.com/high-risk/list`，按站点收录范围抓取，不再按本地 CVSS 阈值过滤。卡片包含 AVD 标识、标题、类型、披露日期、漏洞状态（如 PoC、EXP、武器化）和原文链接，并按需补抓详情中的漏洞描述、解决建议、受影响软件情况和阿里云评分。阿里云评分与 CVSS 分开显示；该列表没有 CVSS 列，因此 CVSS 显示“未知”；只提取标题中明确出现的 CVE 编号，缺失时显示“未提供”，不根据 AVD 编号推导。

原 `aliyun_cve` 类型仍可采集 `/nvd/list`，保留其 CVSS 0 分和未知评分语义。两种漏洞来源均按首次发现时间生成昨日汇总，并排除基线；RSS 与各漏洞来源独立通知，不跨来源合并相同条目。站点独立的 `/nonvd/list` 未接入，但高风险列表内没有 CVE 编号的条目也会被采集。

详情中的受影响软件优先取专用表格，保留厂商、产品、版本及包含/不包含边界；没有表格时仅摘录描述中明确标注的影响版本。防护产品覆盖信息不会作为受影响软件。来源缺失字段显示“来源未提供”，阿里云评分不转换为 CVSS。

首次静默基线不批量抓取详情。基线之后的新条目在生成通知前尝试补齐详情，成功结果存入 SQLite 并复用；旧版尚无详情的非基线记录在再次进入扫描窗口时也会补抓。每个订阅每轮最多 20 次详情请求、总时限 90 秒，未尝试过的条目优先，之后按最早尝试时间重试。详情失败或超出本轮限额时仍发送基础通知，四项详情字段明确显示“暂未获取”，后续轮询继续补齐。已生成的通知内容保持固定，补齐详情不另发增量提醒；后续昨日汇总使用已保存的详情。成功详情为采集时快照，不自动周期刷新。

卡片保留段落、版本范围和建议中的链接；超长字段显示截断提示及原文按钮，按实际 JSON 字节控制单张 18 KiB 上限并拆分汇总。

浏览器使用独立临时配置和最小环境，不继承机器人凭证。普通 HTTP 目前可能收到 WAF 挑战，因此使用 Chromium 渲染后校验业务表格；生产可达性取决于网络和站点策略，浏览器退出成功并不等于有效采集。

## 命令

```sh
sentinel run -config config.yaml       # 常驻服务（默认命令）
sentinel once -config config.yaml      # 抓取、生成到期汇总并处理本轮最多 100 个到期任务
sentinel check -config config.yaml     # 本地配置与凭证格式检查，不发送消息
sentinel send-test -config config.yaml # 每个配置订阅发送两张明确标识的测试卡片
sentinel version                      # 应用版本、Go 编译版本和目标平台
```

`send-test` 会按订阅类型真实发送测试消息，但不读写 SQLite，也不改变生产基线；只测试高风险来源时使用仅含高风险订阅的配置。它测试机器人连通性，不代表真实来源可用。`once` 在来源抓取失败时返回非零退出码，发送失败则保存重试任务；持续重试需要运行常驻服务。

## 开发与构建

```sh
make check test build
bin/sentinel version
make image
```

Makefile 固定 `GOTOOLCHAIN=go1.27.2`。Docker 构建使用 `registry.cn-hangzhou.aliyuncs.com/0x0034/golang:1.27` 并固定 digest；该标签当前内置 Go 1.27.3，因此构建阶段显式下载、使用和校验 Go 1.27.2 工具链。纯 Go SQLite 驱动支持 `CGO_ENABLED=0` 的 amd64 构建。`make image` 构建并加载镜像；`make push` 只推送 `VERSION` 对应标签（默认 `0.2.0-rc.3`），候选版本不更新 `latest`。

运行基础镜像使用 `registry.cn-hangzhou.aliyuncs.com/0x0034/alpine:3.22` 并固定 digest。APK 软件源使用 `https://mirrors.aliyun.com/alpine/`，安装 Chromium 和 TLS 证书前完成替换。`APK_DOWNLOAD_BASE` 构建参数默认也是该源，可在构建机器上指向同源缓存转发以改善下载速度；不改变最终镜像的 APK 源或运行环境。Alpine 包签名验证始终启用。

构建时 `GOPROXY` 默认使用 `https://goproxy.cn,direct`，保持 Go 默认校验机制。可用 `docker buildx build --build-arg GOPROXY=...` 按环境覆盖。

测试使用临时 SQLite、RSS/HTML 样例、本地 HTTP 服务和模拟浏览器，不调用真实机器人。覆盖跨时区日期边界、基线与增量、修改去重、故障和重启恢复、分片、业务响应、共享目标节流、数据库迁移、完整分页及浏览器生命周期。

设计见 [RSS 方案](docs/design/rss-feishu.md)、[漏洞库方案](docs/design/aliyun-vulnerability-source.md)、[领域词汇](GLOSSARY.md) 和 [投递决策](docs/adr/0001-durable-notification-delivery.md)。详情补充验收见 [rc.3 记录](docs/verification/2026-10-22-details.md)，高风险来源验收见 [高风险来源验收记录](docs/verification/2026-10-22-high-risk.md)，此前 CVE 验收见 [rc.1 验收记录](docs/verification/2026-10-22-cve.md)，历史版本见 [0.1.0 验收记录](docs/verification/2026-10-22.md)。
