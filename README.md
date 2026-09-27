# cfhub

众包的 Cloudflare 优选 IP：linux.do 用户在自己的线路上跑一个探针（cfprobe），用 ECH 实测 Cloudflare IP 并上报；cfhub 按运营商投票出各自的优选池，公开展示，并推送给 edge DoH，让不同运营商的用户拿到适合自己线路的 IP。

- 公开实例：https://cfhub.1molchuan.top
- 协议：[AGPL-3.0](LICENSE)

| 目录 | 内容 |
|---|---|
| `echprobe/` | 探针源码。志愿者安装的 `cfprobe` 就是它编译出来的程序 |
| `cfhub/` | 汇总服务（Go + SQLite）：linux.do 登录、token、接收上报、投票、看板、API、管理后台、安装脚本 |

## 志愿者的机器上跑了什么

安装脚本（`cfhub/scripts/install.sh.tmpl`、`install.ps1.tmpl`）做的事：

1. 下载 `cfprobe`，核对 sha256，对不上就拒绝安装。先从镜像下载，失败再从 cfhub 本站下载。
2. Linux：建一个无登录权限的系统用户 `cfprobe`；token 存在 `/etc/cfprobe/token`（仅 root 和 cfprobe 组可读）；装一个每小时运行一次的 systemd timer。Windows：文件放在 `%ProgramData%\cfprobe`，只有 SYSTEM 和管理员可读，并注册一个每小时运行的计划任务。
3. 每次运行两条命令：

```
cfprobe -hub https://cfhub.1molchuan.top -token-file /etc/cfprobe/token -history /var/lib/cfprobe/history4.json
cfprobe -hub https://cfhub.1molchuan.top -token-file /etc/cfprobe/token -history /var/lib/cfprobe/history6.json -family 6
```

不开放任何端口，不代理任何流量，不修改系统 DNS 或网络设置。卸载：`curl -fsSL https://cfhub.1molchuan.top/install.sh | sudo bash -s -- --uninstall`，会删除程序、配置、状态文件、systemd 单元和系统用户。

### 一次运行的过程（`echprobe/hub.go`）

1. 向 cfhub 要候选 IP（`GET /api/v1/probe/candidates`）：你所在线路类别的当前池，加上同类线路其他探针最近上报的前几名。
2. 收集更多候选：内置的 26 个社区优选域名，每个随机取 6 个 IP，通过 AliDNS（`https://223.5.5.5/dns-query`）解析；再从 Cloudflare 网段随机抽 30 个；加上本机历史上表现最好的 150 个。
3. 从 edge DoH（`https://edge.1molchuan.top/dns-query`）取 Cloudflare 当前的 ECH 公钥。
4. 对每个候选 IP 做 6 次 TLS 握手，交替用 `x.com` 和 `linux.do` 作为目标，内层域名用 ECH 加密，外层是 Cloudflare 公共的 `cloudflare-ech.com`。每次握手后请求一次 `/cdn-cgi/trace`，必须返回 200，失败一次就不再测这个 IP。同时最多测 6 个 IP，一轮最多 8 分钟。
5. 筛选：本轮全部成功，历史成功率不低于 90%，延迟不比最快的明显慢。
6. 上报（`POST /api/v1/probe/report`），内容就是下面这些，没有别的：

```json
{"family": 4, "version": "cfprobe/1",
 "ips": [{"ip": "104.16.1.1", "median_ms": 180, "ok": 6, "rounds": 6}, ...]}
```

每次运行大约消耗几 MB 流量。

`echprobe` 还有其他模式（`-report`、`-h3check`、`-sitecheck`、`-github` 等），供维护者自己的探测机向 DoH 管理接口上报，需要管理员 token。志愿者安装的命令只用 `-hub` 模式。

### cfhub 保存什么

- 你的 linux.do 账号 id、用户名、显示名、信任等级。
- 探针所在的 /24 网段（IPv6 为 /48）和线路类别。**不保存完整 IP。**
- 测速结果，保留 7 天。
- token 只存 sha256 哈希，丢了只能重新生成。

## 自己核对程序

发布的程序可以从源码逐字节复现。用 Go 1.26.1：

```bash
cd echprobe
GOOS=linux   GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o cfprobe-linux-amd64 .
GOOS=linux   GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o cfprobe-linux-arm64 .
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o cfprobe-windows-amd64.exe .
sha256sum cfprobe-*
```

把结果和 `curl -s https://cfhub.1molchuan.top/install.sh` 里的 `SHA=`，以及 `install.ps1` 里的哈希对比，应该完全一致。

## 线路分类

- 电信、联通、移动、教育网：用 [gaoyifan/china-operator-ip](https://github.com/gaoyifan/china-operator-ip) 的网段表，每天更新。
- 国内云厂商（阿里云、腾讯云、华为云、百度智能云、火山引擎、京东云、金山云）：取各家国内机房的 AS 号，每天从 RIPEstat 拉取这些 AS 宣告的网段。各家的海外 AS 不算在内。
- 其他：境外线路和其他网络。只在看板上展示，不单独分池。

上报者的 IP 只信任反向代理（Caddy 的 `header_up X-Real-IP {remote_host}`）写入的地址，客户端自己带的 `X-Real-IP` 无效。

## 投票规则（`cfhub/aggregate.go`、`cfhub/rank.go`）

每 5 分钟汇总一次最近 150 分钟内的上报，按"线路类别 + 地址族"分组：

- 一个网段算一票，取这个网段最新的一份上报。同一条线路上开再多账号，也只算一票。
- 一个人在同一个池里最多算 5 台机器。
- IP 入池要同时满足：超过一半的探针上报了它；认可它的探针至少来自 2 个不同的人；同一个 /24 最多选 2 个。按票数、平均排名排序，取前 6 个。
- 发布条件：不是"其他"类，管理员没有暂停，至少 2 个不同的人参与，选出的 IP 至少 2 个。
- 上报的 IP 必须在 Cloudflare 公布的网段内，否则丢弃。

已发布的池会推送给 DoH（`CFHUB_DOH_URL` + `HUB_TOKEN`，每 5 分钟一次，有效期 30 分钟）。推送用的令牌只能写运营商池。cfhub 停止后，DoH 里的运营商池会自然过期，回到全国池。

## 公开 API

- `GET /api/v1/pools`：各类线路当前的池、参与人数和台数、是否已发布。
- `GET /api/v1/history?isp=chinanet&family=4&hours=48`：池子的变化历史。
- `GET /api/v1/summary`：各类线路的活跃探针数。

## 自己部署 cfhub

```bash
cd cfhub && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o cfhub .
```

用环境变量配置（完整列表见 `cfhub/main.go` 的 `loadConfig`）：

| 变量 | 说明 |
|---|---|
| `CFHUB_PUBLIC_URL` | 对外地址，必填 |
| `CFHUB_SESSION_KEY` | 至少 32 个字符的随机串，必填 |
| `LINUXDO_CLIENT_ID` / `LINUXDO_CLIENT_SECRET` | 在 connect.linux.do 注册的应用，回调地址为 `<公开地址>/auth/callback` |
| `CFHUB_ADMINS` | 管理员的 linux.do 账号 id，逗号分隔 |
| `CFHUB_MIN_TRUST` | 最低信任等级，默认 1 |
| `CFHUB_DATA_DIR` | 数据目录，默认 `/var/lib/cfhub`；探针程序放在其中的 `dist/` |
| `CFHUB_DL_MIRRORS` | 可选，探针下载镜像，逗号分隔的 https 地址 |
| `CFHUB_DOH_URL` / `HUB_TOKEN` | 可选，推送池子的 DoH 管理接口；`HUB_TOKEN` 为空时只计算不推送 |

cfhub 默认只监听 `127.0.0.1:8790`，前面需要一个反向代理。反向代理必须用真实的对端地址覆盖 `X-Real-IP`，并挡住 `/internal/*`：

```
cfhub.example.com {
	@internal path /internal/*
	respond @internal "Not found" 404
	reverse_proxy 127.0.0.1:8790 {
		header_up X-Real-IP {remote_host}
	}
}
```

域名要直连源站，不能套会改写客户端地址的 CDN，否则 cfhub 拿不到上报者的真实 IP。

## 测试

```bash
cd cfhub && go test ./...
cd echprobe && go test ./...
```
