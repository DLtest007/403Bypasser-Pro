# 403 Bypasser Pro

基于 Java 11 深度重构的自动化 403/401 绕过与 WAF 智能对抗 Burp Suite 插件。

本项目在传统 403 绕过工具的基础上，引入了 **多线程高并发架构**、**绝对精准的字节级 Diff 算法**，以及独创的 **WAF 智能探活与 PoC 动态拉黑机制**。专为现代 Web 复杂鉴权绕过场景与高强度红队实战打造，彻底告别“一扫就封 IP”的痛点。

## 🔥 核心实战特性

### 🛡️ WAF 智能防御对抗引擎 (独家)
* **实战指纹库：** 内置 12+ 款国内外主流 WAF 指纹（涵盖 Cloudflare、阿里云、腾讯云、安全狗、长亭等），支持在 UI 界面免重启动态热更新自定义指纹库。
* **IP 封禁智能探活 (Anti-Ban)：** 命中 WAF 拦截时，底层会自动补发安全 Base 包。若 Base 包也被拦截，瞬间判定 `[IP 已被墙]` 并自动熔断该站点的后续发包，完美保护出口 IP。
* **PoC 动态黑名单：** 若判定 IP 存活但特定 PoC 违规，自动将该 Payload 丢入站点黑名单，避免重复无效触发 WAF 规则。
* **WAF 情报中心：** 独立的 UI 可视化大屏，实时监控各站点的 WAF 类别、IP 存活状态与拦截统计。

### ⚡ 极限性能与精准度
* **精准字节级 Diff：** 彻底抛弃易受分块传输和 GZIP 干扰的 `Content-Length`，纯字节切片分离 Header 与 Body，长度差异 100% 精确，从根源上消灭误报。
* **双正则 200 捕获引擎：** 针对前后端分离架构，动态编译正则引擎自动捕获 `{"code":-1}`、`未授权` 等假 200 数据包，强制触发绕过逻辑。
* **内存隔离并发：** 采用 `ConcurrentHashMap` 与 `volatile` 变量读写分离，后台多线程狂扫发包的同时，前台 UI 随意修改 7 大配置表，绝不卡死。

### 🧰 深度 Bypass 字典与算法
* 预置重火力极限 Fuzz 字典（包含 `..;/`, `%2e%2e%3b`, `X-HTTP-Host-Override`, `True-Client-IP` 等）。
* 智能 HTTP 动词篡改与协议降级（严谨的 Body 清理与 `Content-Length` 自动补偿机制，防 400 Bad Request 报错）。
* 多节点路径打断重组算法，智能适配不同目录层级。

## ⚙️ 安装与使用

项目已配置 GitHub Actions 全自动 CI/CD 流水线。

**方式一：一键下载（推荐）**
前往项目右侧的 **[Releases]** 页面，下载最新自动编译的 `403Bypasser-*.jar`，在 Burp Suite 的 Extender 中导入即可使用。

**方式二：自行编译**
```bash
git clone [https://github.com/YourUsername/403Bypasser-Pro.git](https://github.com/YourUsername/403Bypasser-Pro.git)
cd 403Bypasser-Pro
mvn clean package
