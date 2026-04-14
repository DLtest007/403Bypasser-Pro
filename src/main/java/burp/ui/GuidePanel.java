package burp.ui;

import javax.swing.*;
import java.awt.*;

public class GuidePanel extends JPanel {
    public GuidePanel() {
        super(new BorderLayout());
        this.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));

        JTextArea helpText = new JTextArea("【403 Bypasser Pro - 核心功能与字典编写完全指南】\n\n" +
                        "为了发挥本插件的最大威力，请务必仔细阅读以下各模块的配置规则。本插件所有配置均支持【极速热加载】，修改后点击任意空白处或敲击回车，即可瞬间生效至底层引擎，无需重启插件！\n\n" +
                        "--- [1] 📂 路径与参数 (Query) ---\n" +
                        "作用：通过在 URL 路径中插入特殊字符（如 ../, %2e%2e/, ; 等）来绕过反向代理或网关的 ACL 限制。\n" +
                        "用法：一行一个 Payload。底层引擎会自动将这些字符变异并插入到 URL 的各个目录层级中进行 Fuzzing。\n\n" +
                        "--- [2] 🕵️ 请求头伪造 (Header) ---\n" +
                        "作用：利用 HTTP 头部（如 X-Forwarded-For 等）欺骗后端服务器，使其认为请求来自本地或内网可信 IP。\n" +
                        "用法：必须遵循 \"Header名: Header值\" 的格式。例如：\n" +
                        "X-Real-Ip: 127.0.0.1\n\n" +
                        "--- [3] 🔄 动词篡改 (Method) ---\n" +
                        "作用：有些鉴权机制只对 GET/POST 生效，篡改 HTTP 请求方法可以绕过这类限制。\n" +
                        "用法：必须使用 \"->\" 符号表示替换规则。例如：GET -> POST\n\n" +
                        "--- [4] ⏭️ 静态资源放行 & ✅ 域名白名单 ---\n" +
                        "Exclude：填入不需要扫描的文件后缀（如 .js, .css）。带有这些后缀的请求将被直接跳过，节省发包资源。\n" +
                        "Whitelist：开启白名单匹配后，只有目标域名包含这里填写的关键字时，插件才会发起被动扫描。\n\n" +
                        "--- [5] 🎭 业务拦截关键字 (防假200 OK) ---\n" +
                        "痛点：很多现代系统在拦截请求时，虽然页面提示“未授权”，但状态码依然返回 200 OK，导致扫描器漏报。\n" +
                        "解决：在此处填入拦截页面中出现的标志性文字（如 {\"code\":-1, \"msg\":\"权限不足\"}）。底层会自动转为安全正则。\n\n" +
                        "--- [6] 🛡️ WAF指纹库 (WAF) ---\n" +
                        "作用：配合插件的“IP封禁智能探活”机制，精准识别 WAF 并触发防封黑名单。\n" +
                        "用法：必须严格按照 [WAF名称:正则表达式] 的格式填写！例如 -> Cloudflare: (?i)(cf-ray|cloudflare)\n\n" +
                        "--- [7] 🎯 靶向 CVE / Host 碰撞 / URL 污染 ---\n" +
                        "CVE：直接填入未授权接口路径（如 /api/v1/terminal/sessions/?limit=1），引擎会强制替换原始路径进行打击。\n" +
                        "Host：填入内网 IP 或 localhost，引擎会覆盖原本的 Host 头尝试绕过网关。\n" +
                        "HPP：填入特权参数（如 admin=true），引擎会将其附加在 URL 尾部混淆鉴权。");
        helpText.setEditable(false);
        helpText.setLineWrap(true);
        helpText.setWrapStyleWord(true);
        helpText.setBackground(this.getBackground());
        helpText.setFont(helpText.getFont().deriveFont(14f));
        this.add(new JScrollPane(helpText), BorderLayout.CENTER);
    }
}
