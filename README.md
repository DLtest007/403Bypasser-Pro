🚀 403Bypasser-Pro (Core Engine)
基于 Java 11 开发的自动化 403/401 权限绕过 与 WAF 深度对抗 Burp Suite 插件。

本项目在传统的绕过工具基础上，引入了全新的多态混淆策略与 WAF 熔断探活机制。本次发布的 Core Engine 版本对底层发包引擎进行了彻底重构，旨在通过更精准的协议层欺骗技术（如分块传输、延迟发包）穿透现代云环境与 WAF 的多层防御。

🔥 六大核心绕过模块 (New)
本版本在原有逻辑基础上，新增并优化了以下六大实战模块：

延迟发包模块 (Scan Delay)：支持毫秒级发包延迟设置。通过模拟真人操作速率，有效规避高灵敏度 WAF 的频率阈值拦截。

分块传输引擎 (Chunked Encoding)：自动将攻击包转换为 HTTP 分块传输格式。利用部分 WAF 无法完整重组 HTTP 碎片的缺陷，实现探测路径的“降噪”穿透。

CVE 历史漏洞库 (CVE Probe)：内置针对 SpringBoot、Shiro、Weblogic 等主流框架的常见未授权访问路径。通过上下文感知算法，自动在根路径与子路径下进行双重验证。

Content-Type 欺骗模块：通过伪造 Content-Type（如 application/json 伪装为 image/png）欺骗 WAF 的后缀检查与报文内容扫描。

Host 碰撞模块 (Host Collision)：自动化枚举多种本地环回地址与虚拟主机头（Host Header），尝试绕过基于域名或内网访问限制的鉴权逻辑。

HPP 参数污染模块：通过 HTTP 参数污染技术（如 admin=true）探测目标业务逻辑在处理重名参数时的解析差异。

🛡️ WAF 智能对抗引擎
指纹精准识别：内置 12+ 款主流 WAF 指纹库，支持在 UI 界面实时监控目标的防御态势。

IP 自动探活 (Anti-Ban)：独创熔断机制。当命中拦截时自动比对 Base 包，一旦判定 IP 被墙，立即熔断后续扫描，保护红队资产。

字节级 Diff 算法：抛弃易受干扰的长度对比，采用纯字节流切片算法，确保在高并发环境下绕过成功的判定精度。

⚙️ 界面与交互升级
UI 彻底重构：全新的可视化大屏设计。Scan Task 标签页支持详细的 Payload 追踪，WAF Info 面板提供实时的拦截统计与 IP 状态显示。

黑白名单策略：支持通过正则过滤图片、JS、CSS 等冗余资源，大幅提升实战中的有效发包率。

🛠️ 安装与编译
环境要求
Java 11+

Maven 3.x

编译指令
Bash
git clone https://github.com/DLtest007/403Bypasser-Pro.git
cd 403Bypasser-Pro
mvn clean package
编译完成后，在 target/ 目录下获取 403Bypasser-1.2-SNAPSHOT.jar 即可。

⚠️ 免责声明
本工具仅面向 合法授权的渗透测试及安全审计 场景。在使用本工具进行测试时，应遵守当地法律法规。因用户非法使用造成的任何后果，由使用者自行承担，作者不承担任何法律及连带责任。

DLtest007 | 403Bypasser-Pro Project Team
