# MyIP

IP 地址、网络归属和纯净度检测，运行于 **https://ip.junxinzhang.com/**。
在原 MyIP 上迭代，保留 `/classic/` 经典版与 `/simple/` 简洁版。

## 功能

- 自动检测访问者的当前公网 IP，支持手动查询 IPv4 / IPv6。
- 展示参考纯净度、七项风险信号、位置、网络运营商及 ASN。
- 将 proxycheck.io 与 ipwho.is 的位置和归属并排展示，不将位置差异计入风险。
- 支持隐藏、复制 IP；按需执行浏览器网站访问检查。
- 超时、限额和缺失字段明确显示「未知」或「数据不足」，不会自动视为安全。

## 评分与边界

参考纯净度 = `100 - proxycheck.io v3 detections.risk`，范围 0–100，越高表示该来源记录的风险越低。
风险值 0–33 为「记录风险较低」、34–65 为「需要留意」、66–100 为「风险较高」。
无有效数字风险值时不显示分数。七项信号分别为代理、VPN、Tor、机房、受控设备、自动采集、匿名网络。
只有明确的布尔 `false` 才显示「未发现」，缺失或异常字段显示「未知」。
这些结果来自第三方数据库，可能过时或误判，不等同于独立信誉认证，不保证 AI、流媒体或其他平台可用。
机房、VPN 等标记只说明网络特征，不单独证明恶意行为。

## 本地运行

使用 Node.js 22：

```sh
npm ci
npm test
npm run dev
```

打开终端显示的本地地址。`npm run dev` 先构建页面，再同时运行静态页面和 `/api/check`。

## 部署到 ZKUAT / 自有服务器

完整检测需要常驻查询服务。GitHub Pages 仅支持静态页面，不能单独运行本项目的风险查询服务。
Vercel 自动发布已在仓库配置中关闭。

本机先运行 `npm ci && npm run build`，再运行 `npm start`，即可启动独立服务。
默认监听本机 4173 端口；可通过 `HOST`、`PORT` 修改。

也可在服务器上运行：

```sh
docker compose -f deploy/compose.yml up -d --build
```

容器只向本机开放 28473 端口。由现有网站入口将域名转到此端口，配置示例见 `deploy/nginx.conf.example`。
启用 `TRUST_PROXY=true` 时，入口必须覆盖传入的 `X-Forwarded-For`，不要透传用户自带的该字段。
`/healthz` 用于服务存活检查；风险与位置查询仍由 `/api/check` 提供。
更新前保留上一份发布目录和入口配置，即可快速切回。

默认使用 proxycheck.io 的免密额度（官方当前为服务器出口 IP 共享的每日 100 次），适合轻量使用。
可在服务器环境中设置 `PROXYCHECK_API_KEY` 以使用自己的额度；免费注册账户目前为每日 1,000 次。
实际额度以数据源最新政策为准。额度不足会正常显示「数据不足」，不会伪造评分。
服务实例对成功查询缓存 10 分钟，错误短暂缓存 30 秒；每个访问者在单个实例中限制每分钟 20 次。
这不是跨实例的全局配额保护；高访问量应配合平台限流和合适的上游额度。

## 隐私与安全

获取当前 IP 时，浏览器依次尝试 ipify / ipify IPv6 / ipwho.is。
风险和位置查询在服务器上向 proxycheck.io、ipwho.is 发起，只发送所查 IP；密钥仅留在服务器。
工具不写入数据库或查询历史，仅有实例内的短期缓存；服务器提供商和数据提供商仍适用各自日志政策。
不接受域名、内网、回环、文档和保留地址；不能用此服务指定任意上游网址。
第三方数据以文字方式展示，不作为 HTML 执行。

资料：[proxycheck.io 文档](https://proxycheck.io/api/)、[ipwhois.io 文档](https://ipwhois.io/documentation)。

## 致谢

原项目基于 [SukkaW/MyIP](https://github.com/SukkaW/MyIP)，MIT 协议。
原作者 Sukka，参考提交 `38a82d05f88c40136782742661a177b46d0aaddc`；保留原 LICENSE。
本次页面的信息组织参考 [Net.Coffee IP 查询](https://ip.net.coffee/ip/)，独立实现，不调用其私有查询服务。

## 页面回归验证

先启动 `npm run dev`，再运行 `npm run test:browser`。macOS 默认使用已安装的 Google Chrome；其他环境先运行 `npx playwright install chromium`。可通过 `MYIP_CHROME` 指定浏览器路径、`MYIP_TEST_URL` 指定测试站点。
`node scripts/browser-check.cjs --live` 在模拟异常与交互检查之外，还会执行真实的当前 IP 和手动 IP 查询。截图输出至被忽略的 `outputs/` 目录。
