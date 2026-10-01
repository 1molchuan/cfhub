# cfhub

众包的 Cloudflare 优选 IP：linux.do 用户在自己的线路上跑一个探针（cfprobe），用 ECH 实测 Cloudflare IP 并上报；cfhub 按运营商投票出各自的优选池，公开展示，并推送给 edge DoH，让不同运营商的用户拿到适合自己线路的 IP。

- 公开实例：https://cfhub.1molchuan.top
- 协议：[AGPL-3.0](LICENSE)
- 使用这些池子的 DoH 也已开源：[github.com/1molchuan/edge-smart-doh](https://github.com/1molchuan/edge-smart-doh)。它怎样判断访问者的运营商、怎样在运营商池、全国池和其他池子之间选择，以及 cfhub 推送的令牌能做什么、不能做什么，都写在它的 README 里（"和 cfhub 的关系"一节）。

| 目录 | 内容 |
|---|---|
| `echprobe/` | 探针源码。志愿者安装的 `cfprobe` 就是它编译出来的程序 |
| `cfhub/` | 汇总服务（Go + SQLite）：linux.do 登录、token、接收上报、投票、看板、API、管理后台、安装脚本 |

## 志愿者的机器上跑了什么

安装脚本（`cfhub/scripts/install.sh.tmpl`、`install.ps1.tmpl`）做的事：

1. 检查依赖：curl 或 wget、CA 证书、sha256sum，以及 Linux 上的 useradd。缺哪个就用系统的包管理器装哪个（apt-get、dnf、yum、zypper、pacman、opkg、apk），不装别的。
2. 按平台选程序：x86_64、arm64、32 位 ARM（ARMv5 及以上）、MIPS 大端和小端（软浮点，适用于 MT7621、ath79 等路由器芯片）。下载 `cfprobe`，核对 sha256，对不上就拒绝安装。先从镜像下载，失败再从 cfhub 本站下载。
3. Linux：建一个无登录权限的系统用户 `cfprobe`；程序和状态文件放在 `/var/lib/cfprobe`（属于 cfprobe 用户）；token 存在 `/etc/cfprobe/token`（仅 root 和 cfprobe 组可读）；装一个每小时运行一次的 systemd timer，以 cfprobe 用户运行，除 `/var/lib/cfprobe` 外文件系统只读。Windows：文件放在 `%ProgramData%\cfprobe`，只有 SYSTEM 和管理员可读，并注册一个每小时运行的计划任务。
   OpenWrt（`wget -qO- https://cfhub.1molchuan.top/install.sh | sh -s -- <token>`）：同样建 `cfprobe` 用户；程序放在闪存上的 `/usr/lib/cfprobe`（OpenWrt 的 `/var` 在内存里），可以用 `--dir` 放到 U 盘；由 cron 以 cfprobe 用户每小时运行一次，输出进系统日志（`logread -e cfprobe`），并把程序和配置写进 `/etc/sysupgrade.conf`，升级固件后保留。
4. 每次运行两条命令：

```
/var/lib/cfprobe/cfprobe -hub https://cfhub.1molchuan.top -token-file /etc/cfprobe/token -history /var/lib/cfprobe/history4.json
/var/lib/cfprobe/cfprobe -hub https://cfhub.1molchuan.top -token-file /etc/cfprobe/token -history /var/lib/cfprobe/history6.json -family 6
```

不开放任何端口，不代理任何流量，不修改系统 DNS 或网络设置。卸载：`curl -fsSL https://cfhub.1molchuan.top/install.sh | sudo bash -s -- --uninstall`，会删除程序、配置、状态文件、systemd 单元和系统用户（OpenWrt 用 `wget -qO- ... | sh -s -- --uninstall`，同时删掉 cron 任务和 sysupgrade 条目）。

### 开着代理的机器：直连选项（`echprobe/direct.go`）

机器上开着 TUN 模式的代理（sing-box、Clash、WireGuard 等）时，探针的流量也会被代理接管，测到的是代理线路，结果会被归到"其他"。加上直连选项后，探针的所有连接都从物理网卡直接发出，包括测速握手、DoH 查询、上报和自动更新，绕开 TUN；域名通过同一张网卡向 223.5.5.5 查询，不用代理可能返回的假 IP。它用的是代理软件自己直连时用的套接字选项：macOS 用 `IP_BOUND_IF`，Linux 用 `SO_BINDTODEVICE`，Windows 用 `IP_UNICAST_IF`。不改系统和代理的任何设置。

- Linux / OpenWrt：安装命令末尾加 `--direct`（自动选网卡）或 `--direct=eth0`。
- Windows：加 `-Direct auto`。
- Docker：加 `-e CFPROBE_DIRECT=auto`（需要 `--network host`）。
- 直接运行：`cfprobe -direct auto ...` 或 `-direct en0`。

自动选网卡的规则：已启用、有硬件地址、不是点对点隧道或虚拟网桥、有对应地址族公网地址的网卡里，系统顺序最靠前的那个。运行时第一行会打印选中的网卡。PPPoE 拨号的路由器上，公网地址在 `pppoe-wan` 这类点对点接口上，自动选择选不到它，请写明 `--direct=pppoe-wan`。

### 路由器上的透明代理（OpenClash、PassWall 等）

透明代理会在防火墙的 OUTPUT 规则里把路由器自身的连接也转给代理（REDIRECT 或打 fwmark 走策略路由）。直连选项只决定从哪张网卡发出，**绕不过这些防火墙规则**：探针要么测到的是代理线路，要么绑定 WAN 后连接超时。

- **OpenClash**：安装脚本检测到 `/etc/init.d/openclash` 时，让探针以组 65534 运行。OpenClash 在它所有的输出链（fw4 和 iptables 两种模式）里都放行这个组，这是它自己的内核运行时用的组，所以探针的流量直接从路由器的线路出去，不用改 OpenClash 的任何设置。这时探针读的令牌文件归它自己所有（只读），配置目录仍归 root，探针改不了自己的配置。先装探针、后装 OpenClash 的，重新运行一次安装命令即可。
- **其他透明代理**：安装脚本只给出提示。请在代理的设置里让用户 `cfprobe`（或路由器自身的流量）直连。

### macOS

发布版里有 macOS 的程序（`cfprobe-darwin-arm64`、`cfprobe-darwin-amd64`），可以自动更新，但安装脚本还不支持 macOS，需要手动配置：程序放在 `~/Library/Application Support/cfprobe`，用 LaunchAgent（`StartInterval` 3600）每小时依次运行 IPv4 和 IPv6 两轮，不需要 sudo。

### Docker（`docker/`）

适合 NAS 和已经在用 Docker 的机器。镜像支持 amd64、arm64、32 位 ARM，约 14MB：

```bash
docker run -d --name cfprobe --restart unless-stopped --network host \
  -e CFHUB_TOKEN=<你的 token> -v cfprobe-data:/data ghcr.io/1molchuan/cfprobe:latest
```

或者用 [`docker/compose.yaml`](docker/compose.yaml)：填好 token，然后运行 `docker compose up -d`。大陆访问 ghcr.io 慢的话，把镜像地址换成南京大学的镜像站：`ghcr.nju.edu.cn/1molchuan/cfprobe:latest`。

- 用 `--network host`，测的才是这台机器自己的线路；有 IPv6 时也会测 IPv6。容器不开放任何端口。
- 每小时先测 IPv4，再测 IPv6，和 systemd、cron 的安装方式一样。探针以 nobody 用户运行，状态文件放在 `/data` 卷里。日志用 `docker logs cfprobe` 查看。
- 自动更新默认开启：签名有效的新版本装进 `/data`，校验方式和其他安装方式相同；换了新镜像，就改用新镜像自带的程序。不想自动更新，加 `-e CFPROBE_AUTO_UPDATE=0`，之后要升级就拉新镜像。
- token 也可以放在文件里，用 `CFHUB_TOKEN_FILE` 指定（例如 Docker secret），这样 `docker inspect` 看不到它。
- 镜像由 GitHub Actions 从源码构建（[`.github/workflows/docker.yml`](.github/workflows/docker.yml)）。里面的程序用和 `build.sh` 相同的工具链和参数编译，与同一提交的签名发布版逐字节一致，构建日志里打印了每个程序的 sha256。
- 自己构建：`docker build -f docker/Dockerfile -t cfprobe .`。在大陆构建可以加 `--build-arg GOPROXY=https://goproxy.cn,direct`，所有依赖仍按 go.sum 校验。

### 自动更新（`echprobe/selfupdate.go`）

每次运行开始时，探针会下载 `manifest.json` 和它的签名 `manifest.json.sig`（约 500 字节），检查有没有新版本。同时满足下面三条才会更新：

- **签名有效**：清单由维护者的 ed25519 私钥签名。私钥只保存在维护者自己的电脑上，从不上传到服务器；公钥写死在源码里（`releasePublicKey`）。所以 cfhub 服务器或下载镜像即使被人控制，也推不了程序。
- **版本号更大**：清单里的 `seq` 必须大于当前程序的 `releaseSeq`。旧版本的清单即使签名有效，也不能拿来把你降级。
- **校验和一致**：下载的程序必须和签名清单里的 sha256 完全一致。

更新以 cfprobe 用户权限进行，只替换 `/var/lib/cfprobe/cfprobe`（Windows 是 `cfprobe.exe`），从下一次运行起生效。任何一步失败都只记一条日志，继续用当前版本测速。

不想自动更新，安装时加参数：Linux 在 token 后面加 `--no-auto-update`，Windows 加 `-NoAutoUpdate`。之后想升级，就重新运行一次安装命令。

### 上报走哪条路

签名清单里还有一项 `api`：转发 cfhub 探针接口（`/api/v1/probe/*`）的地址。目前是 `https://edge.1molchuan.top`，这是一个香港 CDN 边缘节点，大陆线路连它比直连 cfhub 源站稳定。探针按顺序尝试：先走清单里的地址，连不上（超时、连接失败）再直连 cfhub。只要收到 HTTP 响应（包括拒绝），就不会再换路线重发，所以同一份上报不会发两次。

这个地址写在签名清单里，所以 cfhub 服务器或镜像改不了你的上报去向；以后要换路线，也只需重新签一份清单，不用发新版本。即使关闭了自动更新，也会用清单里的地址。

需要知道的是：走这条路时，HTTPS 连接在 CDN 节点上解开，再由节点转发给 cfhub。所以 CDN 节点能看到你的 token、上报内容和你的 IP。CDN 节点会把你的真实 IP 通过 `X-Real-IP` 转给 cfhub，用于判断线路类别。日志里的 `... via https://...` 会写明每次请求走的是哪条路。

### 一次运行的过程（`echprobe/hub.go`）

1. 向 cfhub 要候选 IP（`GET /api/v1/probe/candidates`，路线见上一节）：你所在线路类别的当前池，加上同类线路其他探针最近上报的前几名。
2. 收集更多候选：内置的 26 个社区优选域名，每个随机取 6 个 IP，通过 AliDNS（`https://223.5.5.5/dns-query`）解析；再从 Cloudflare 网段随机抽 30 个；加上本机历史上表现最好的 150 个。
3. 从 edge DoH（`https://edge.1molchuan.top/dns-query`）取 Cloudflare 当前的 ECH 公钥。
4. 对每个候选 IP 做 6 次 TLS 握手，交替用 `x.com` 和 `linux.do` 作为目标，内层域名用 ECH 加密，外层是 Cloudflare 公共的 `cloudflare-ech.com`。每次握手后请求一次 `/cdn-cgi/trace`，必须返回 200，失败一次就不再测这个 IP。同时最多测 6 个 IP，一轮最多 8 分钟。
5. 筛选：本轮全部成功，历史成功率不低于 90%，延迟不比最快的明显慢。
6. 上报（`POST /api/v1/probe/report`），内容就是下面这些，没有别的：

```json
{"family": 4, "version": "cfprobe/5",
 "ips": [{"ip": "104.16.1.1", "median_ms": 180, "ok": 6, "rounds": 6}, ...]}
```

每次运行大约消耗几 MB 流量。

`echprobe` 还有其他模式（`-report`、`-h3check`、`-sitecheck`、`-github` 等），供维护者自己的探测机向 DoH 管理接口上报，需要管理员 token。志愿者安装的命令只用 `-hub` 模式。

### cfhub 保存什么

- 你的 linux.do 账号 id、用户名、显示名、信任等级。
- 探针所在的 /24 网段（IPv6 为 /48）和线路类别。**不保存完整 IP。**
- 测速结果，保留 7 天。
- 每台探针（IPv4 网段）的累计在线小时数和首次上报时间，用于感谢榜；删掉测速结果后仍保留。
- token 只存 sha256 哈希，丢了只能重新生成。

### 看板上公开什么

- 各类线路的池子、参与人数和台数。
- 志愿者地图（`cfhub/region.go`）：近 24 小时内，中国大陆每个省级行政区有几个人、几台探针、各属哪类线路、最近上报时间。**只显示数量，不显示是谁在哪里。** 省份由探针的 IPv4 网段查 [ip2region](https://github.com/lionsoul2014/ip2region) 得到；港澳台和境外的探针不计入地图，只显示总台数。
- 感谢榜：按探针累计在线时长排序（每台探针每有一个小时上报过结果记一小时，一个人的多台探针累加），显示 linux.do 用户名、累计时长、在线台数和加入日期，不显示位置。被封禁的账号不上榜。

## 自己核对程序

发布的程序可以从源码逐字节复现。用 Go 1.26.1，签出与发布版本号（`echprobe/selfupdate.go` 里的 `releaseSeq`）对应的提交，然后：

```bash
./build.sh            # 在 dist/ 下编出八个平台的程序并打印 sha256
```

`build.sh` 用的编译参数是 `CGO_ENABLED=0 go build -buildvcs=false -trimpath -ldflags="-s -w"`。`-buildvcs=false` 不能省：在 git 仓库里编译时，Go 默认会把提交号写进程序，结果就对不上了。

把结果和线上的签名清单对比，应该完全一致：

```bash
curl -s https://cfhub.1molchuan.top/dl/manifest.json
```

清单签名也可以自己验证：公钥就是 `echprobe/selfupdate.go` 里的 `releasePublicKey`，签名是 `manifest.json.sig` 的内容（base64），签名对象是 `manifest.json` 的原始字节。

### 维护者发版

```bash
# 1. 把 echprobe/selfupdate.go 里的 releaseSeq 加 1，提交并推送
./build.sh
(cd cfhub && go run ./cmd/cfrelease -key <私钥文件> -seq <新版本号> -dist ../dist -sources https://edge.1molchuan.top/cfprobe -api https://edge.1molchuan.top)
# 2. 把 dist/ 里的三个程序和 manifest.json、manifest.json.sig 复制到 cfhub 的 dist 目录；清单最后放
```

私钥用 `cfrelease -genkey` 生成，只保存在自己的电脑上。

## 线路分类

- 电信、联通、移动、教育网：用 [gaoyifan/china-operator-ip](https://github.com/gaoyifan/china-operator-ip) 的网段表，每天更新。
- 国内云厂商（阿里云、腾讯云、华为云、百度智能云、火山引擎、京东云、金山云）：取各家国内机房的 AS 号，每天从 RIPEstat 拉取这些 AS 宣告的网段。各家的海外 AS 不算在内。
- 其他：境外线路和其他网络。只在看板上展示，不单独分池。

上报者的 IP 取自反向代理写入的 `X-Real-IP`：
- 直连 cfhub 时，由 Caddy 用 TCP 对端地址覆盖（`header_up X-Real-IP {remote_host}`），客户端自己带的 `X-Real-IP` 无效。
- 经 CDN 节点转发时，使用节点传来的 `X-Real-IP`。

目前没有校验请求是否真的来自 CDN 节点。所以绕过节点、直接连源站并伪造这个头的人，可以冒充别的线路。在它被滥用之前，这个风险由投票规则兜底：每个 IP 都要有 2 个以上不同的人认可才能入池。

## 投票规则（`cfhub/aggregate.go`、`cfhub/rank.go`）

每 5 分钟汇总一次最近 150 分钟内的上报，按"线路类别 + 地址族"分组：

- 一个网段算一票，取这个网段最新的一份上报。同一条线路上开再多账号，也只算一票。
- 一个人在同一个池里最多算 5 台机器。
- IP 入池要同时满足：超过一半的探针上报了它；认可它的探针至少来自 2 个不同的人；同一个 /24 最多选 2 个。按票数、平均排名排序，取前 6 个。
- 发布条件：不是"其他"类，管理员没有暂停，至少 2 个不同的人参与，选出的 IP 至少 2 个。
- 上报的 IP 必须在 Cloudflare 公布的网段内，否则丢弃。

**全国池**（`national`，同样在 `aggregate.go`）：把电信、联通、移动、教育网、国内云厂商中**已发布**的池汇总成一个，每类线路算一份，志愿者多的线路不会压过其他线路。先选多类线路都认可的 IP（认可的线路越多越靠前，同样多时比平均名次），剩下的位置轮流用各线路自己最好的 IP 补上，同一个 /24 最多 2 个。至少 2 类线路的池已发布时，全国池才发布。"其他"类（境外等）不参与。DoH 把全国池给不属于这几类线路的访问者，也用它补某类线路缺少的 IPv4 / IPv6；全国池过期后，退回维护者自己几台探测机的池。

已发布的池会推送给 DoH（`CFHUB_DOH_URL` + `HUB_TOKEN`，每 5 分钟一次，有效期 30 分钟）。推送用的令牌只能写运营商池。cfhub 停止后，DoH 里的运营商池会自然过期，回到全国池。DoH 一侧怎样使用这些池子，见 [edge-smart-doh](https://github.com/1molchuan/edge-smart-doh#和-cfhub-的关系)。

## 公开 API

- `GET /api/v1/pools`：各类线路当前的池、参与人数和台数、是否已发布。
- `GET /api/v1/history?isp=chinanet&family=4&hours=48`：池子的变化历史。
- `GET /api/v1/summary`：各类线路的活跃探针数。
- `GET /api/v1/regions`：近 24 小时中国大陆各省的志愿者人数、探针台数和线路分布（只有数量）。

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
| `CFHUB_IP2REGION_BASE` | 可选，下载 `ip2region_v4.xdb`（约 11MB，每周更新，校验后才替换）的地址，默认 ip2region 仓库的 GitHub raw |

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

## 备份（`cfhub/backup/`）

cfhub 服务器每天做一次备份：数据库在线快照（先做完整性检查）加上配置文件，打包后用 [age](https://age-encryption.org) 加密给维护者的公钥。本机保留最近 7 份，再推送到异地接收端。解密用的私钥只在维护者自己的电脑上，服务器和接收端都只有密文。一份备份目前约 64KB。

- `cfhub-backup.sh` + `cfhub-backup.service/.timer`：服务器上的发送端。配置在 `/etc/cfhub-backup/`：`recipient` 放 age 公钥，`id_ed25519` 是推送用的 SSH 密钥，`known_hosts` 固定接收端的主机公钥，`targets` 每行一个 `user@host[:port]`。
- `receiver.sh`：帮忙存备份的人在自己的机器上以 root 运行一次：

  ```bash
  curl -fsSL <receiver.sh 地址> | sudo bash -s -- '<cfhub 服务器的公钥>' ['<维护者恢复用的公钥>']
  ```

  它会建一个无密码用户 `cfhub-backup`，只允许给定的公钥登录，登录后只能执行 `put`（上传）、`list`（列出）、`get <名字>|latest`（取回）：没有 shell、不能转发端口，只接受 age 加密文件。最多保留 30 份、总共不超过 1GB，50 分钟内最多收一份（即使 cfhub 服务器被入侵，也没法在短时间内用垃圾文件挤掉历史备份）。脚本不改 sshd 配置，不开端口，不装软件，没有后台服务。卸载：`... | sudo bash -s -- --uninstall`。

恢复：

```bash
ssh cfhub-backup@<接收端> get latest > backup.age
age -d -i <私钥文件> backup.age | tar -xzf -     # 得到 hub.db、env、MANIFEST
```

## 测试

```bash
cd cfhub && go test ./...
cd echprobe && go test ./...
```

## 第三方数据

- 地图底图：[DataV.GeoAtlas](https://datav.aliyun.com/portal/school/atlas/area_selector)（阿里云，数据来自高德），包括台湾、香港、澳门、藏南和南海诸岛（九段线）。`cfhub/cmd/mapgen` 把它投影、简化成 `cfhub/geo/china.json`：

  ```bash
  curl -o china.json https://geo.datav.aliyun.com/areas_v3/bound/100000_full.json
  cd cfhub && go run ./cmd/mapgen -in ../china.json -out geo/china.json
  ```

- IP 定位：[ip2region](https://github.com/lionsoul2014/ip2region)（Apache-2.0），运行时下载数据文件，不随仓库分发。
- 运营商网段：[gaoyifan/china-operator-ip](https://github.com/gaoyifan/china-operator-ip)；云厂商网段：RIPEstat。
