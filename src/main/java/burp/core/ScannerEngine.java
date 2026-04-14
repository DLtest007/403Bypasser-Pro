package burp.core;

import burp.*;
import burp.models.PayloadResult;
import burp.models.ScanTask;
import burp.models.WafProfile;

import javax.swing.*;
import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.concurrent.atomic.AtomicInteger;

public class ScannerEngine {
    private final BurpExtender ext;
    private final WafDetector wafDetector;

    public ScannerEngine(BurpExtender ext, WafDetector wafDetector) {
        this.ext = ext;
        this.wafDetector = wafDetector;
    }

    public void doScan(IHttpRequestResponse baseMsg, List<String> modes) {
        IHttpService service = baseMsg.getHttpService();
        byte[] origReqBytes = baseMsg.getRequest();
        IRequestInfo origReqInfo = ext.callbacks.getHelpers().analyzeRequest(service, origReqBytes);
        String host = origReqInfo.getUrl().getHost();

        byte[] origRespBytes = baseMsg.getResponse();
        if (origRespBytes == null) {
            try { origRespBytes = ext.callbacks.makeHttpRequest(service, origReqBytes).getResponse(); } catch (Exception ignored) {}
        }
        int origLen = ext.getBodyLength(origRespBytes);

        ScanTask task = new ScanTask(ext.taskCounter.getAndIncrement(), origReqInfo.getMethod(), origReqInfo.getUrl().toString(), origLen);
        SwingUtilities.invokeLater(new BurpExtender.AddTaskRunnable(ext, task));

        List<String> baseHeaders = origReqInfo.getHeaders();
        byte[] baseBody = Arrays.copyOfRange(origReqBytes, origReqInfo.getBodyOffset(), origReqBytes.length);
        String path = origReqInfo.getUrl().getPath();
        String query = origReqInfo.getUrl().getQuery();

        // --- 新增：探活冷却时间戳（定义在 PayloadRunner 外面，doScan 方法里面） ---
        final long[] lastProbeTime = {0};

        // 统一的发包与 WAF 拦截处理函数
        class PayloadRunner {
            void run(String type, String payloadStr, byte[] newReq) {
                // 1. 全局 IP 封禁拦截
                WafProfile profile = ext.wafMap.get(host);
                if (profile != null && profile.isIpBanned) return;

                // 2. 动态黑名单拦截
                if (ext.cEnableDynamicBlacklist && profile != null && profile.blacklistedPoCs.contains(payloadStr)) {
                    return;
                }

                try {
                    if (ext.cRequestDelay > 0) {
                        try { Thread.sleep(ext.cRequestDelay); } catch (InterruptedException ignored) {}
                    }

                    long start = System.currentTimeMillis();
                    IHttpRequestResponse res = ext.callbacks.makeHttpRequest(service, newReq);
                    long time = System.currentTimeMillis() - start;

                    if (res.getResponse() != null) {
                        int nLen = ext.getBodyLength(res.getResponse());
                        int statusCode = ext.callbacks.getHelpers().analyzeResponse(res.getResponse()).getStatusCode();

                        // 3. WAF 探针逻辑
                        String wafDetected = wafDetector.detectWAF(res.getResponse());
                        if (wafDetected != null) {
                            if (profile == null) {
                                profile = new WafProfile();
                                profile.wafName = wafDetected;
                                ext.wafMap.put(host, profile);
                            }

                            if (ext.cEnableDynamicBlacklist) {
                                boolean ipBannedConfirm = false;

                                // 【核心优化】：事件驱动 + 动态智能冷却探活
                                if (ext.cEnableIpBanCheck) {
                                    long currentTime = System.currentTimeMillis();
                                    long dynamicCooldown = Math.max(5000, ext.cRequestDelay * 5);

                                    if (currentTime - lastProbeTime[0] > dynamicCooldown) {
                                        lastProbeTime[0] = currentTime;

                                        // 【核心修复】：构造一个最纯净的 GET / 请求去探活，不要用带敏感参数的原始包！
                                        String rootRequest = "GET / HTTP/1.1\r\n" +
                                                "Host: " + host + "\r\n" +
                                                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n" +
                                                "Accept: */*\r\n" +
                                                "Connection: close\r\n\r\n";

                                        IHttpRequestResponse testBase = ext.callbacks.makeHttpRequest(service, rootRequest.getBytes());

                                        if (testBase.getResponse() != null) {
                                            String probeWaf = wafDetector.detectWAF(testBase.getResponse());
                                            int probeStatus = ext.callbacks.getHelpers().analyzeResponse(testBase.getResponse()).getStatusCode();

                                            // 如果连访问根目录 / 都命中了 WAF 指纹，且不是正常的 200/301/302/404 状态码，说明 IP 真的阵亡了
                                            if (probeWaf != null && probeStatus != 200 && probeStatus != 404 && probeStatus != 401 && probeStatus != 301 && probeStatus != 302) {
                                                ipBannedConfirm = true;
                                            }
                                        }
                                    }
                                }

                                if (ipBannedConfirm) {
                                    profile.isIpBanned = true;
                                    ext.callbacks.printOutput("[!] 危险警告: " + host + " 的 IP 已被 " + wafDetected + " 封禁！自动终止该站点的后续扫描。");
                                } else {
                                    // IP 没墙，拉黑这个惹事的 PoC
                                    profile.blacklistedPoCs.add(payloadStr);
                                    ext.callbacks.printOutput("[-] PoC 拦截: '" + payloadStr + "' 触发了 WAF，已动态加入该站点黑名单。");
                                }
                                wafDetector.updateWafUI(host);
                            }
                        }

                        // 如果已经被墙了，这条垃圾数据就没必要显示在前端结果表格里了
                        if (profile != null && profile.isIpBanned) return;

                        PayloadResult pr = new PayloadResult(type, payloadStr, nLen, nLen - origLen, (int)time, statusCode, res);
                        SwingUtilities.invokeLater(new BurpExtender.AddPayloadRunnable(ext, task, pr));
                    }
                } catch (Exception ignored) {}
            }
        }
        PayloadRunner runner = new PayloadRunner();

        if (modes.contains("query")) {
            for (String payload : ext.cQueryPayloads) {
                for (String pTest : generatePermutations(path, payload)) {
                    try {
                        List<String> newHeaders = new ArrayList<>(baseHeaders);
                        String firstLine = newHeaders.get(0);
                        String[] parts = firstLine.split(" ");
                        if (parts.length >= 2) {
                            String newUri = pTest;
                            if (query != null) newUri += "?" + query;
                            newHeaders.set(0, parts[0] + " " + newUri + (parts.length >= 3 ? " " + parts[2] : ""));
                        }

                        String displayPayload = path.length() > 1 ? pTest.replace(path, "...") : pTest;
                        runner.run("Query", displayPayload, ext.callbacks.getHelpers().buildHttpMessage(newHeaders, baseBody));

                    } catch (Exception ignored) {}
                }
            }
        }

        if (modes.contains("header")) {
            for (String payload : ext.cHeaderPayloads) {
                try {
                    List<String> newHeaders = new ArrayList<>(baseHeaders);
                    String headerKey = payload.split(":")[0].trim().toLowerCase();
                    boolean updated = false;
                    for (int i = 0; i < newHeaders.size(); i++) {
                        if (newHeaders.get(i).toLowerCase().startsWith(headerKey + ":")) {
                            newHeaders.set(i, payload); updated = true; break;
                        }
                    }
                    if (!updated) newHeaders.add(payload);
                    runner.run("Header", payload, ext.callbacks.getHelpers().buildHttpMessage(newHeaders, baseBody));
                } catch (Exception ignored) {}
            }
        }

        if (modes.contains("method")) {
            for (String payload : ext.cMethodPayloads) {
                if (!payload.contains("->")) continue;
                String[] parts = payload.split("->");
                String from = parts[0].trim();
                String to = parts[1].trim();

                try {
                    List<String> newHeaders = new ArrayList<>(baseHeaders);
                    byte[] newBody = baseBody.clone();
                    String firstLine = newHeaders.get(0);

                    if (firstLine.contains(from)) {
                        newHeaders.set(0, firstLine.replaceFirst(from, to));

                        if (to.equals("GET") || to.equals("HEAD") || to.equals("OPTIONS") || to.equals("TRACE")) {
                            newHeaders.removeIf(h -> h.toLowerCase().startsWith("content-length:") || h.toLowerCase().startsWith("content-type:"));
                            newBody = new byte[0];
                        } else if (to.equals("POST") || to.equals("PUT")) {
                            boolean hasCl = newHeaders.stream().anyMatch(h -> h.toLowerCase().startsWith("content-length:"));
                            if (!hasCl) newHeaders.add("Content-Length: " + newBody.length);
                        }
                        runner.run("Method", payload, ext.callbacks.getHelpers().buildHttpMessage(newHeaders, newBody));
                    }
                } catch (Exception ignored) {}
            }
        }

        // 4. 分块传输绕过 (Chunked Encoding)
        if (modes.contains("chunked") && baseBody.length > 0) {
            try {
                List<String> newHeaders = new ArrayList<>(baseHeaders);
                newHeaders.removeIf(h -> h.toLowerCase().startsWith("content-length:"));
                newHeaders.add("Transfer-Encoding: chunked");
                String hexLen = Integer.toHexString(baseBody.length);
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                baos.write((hexLen + "\r\n").getBytes()); baos.write(baseBody); baos.write("\r\n0\r\n\r\n".getBytes());
                runner.run("Chunked", "Transfer-Encoding: chunked", ext.callbacks.getHelpers().buildHttpMessage(newHeaders, baos.toByteArray()));
            } catch (Exception ignored) {}
        }

        // 5. Content-Type 解析欺骗
        if (modes.contains("content_type") && baseBody.length > 0) {
            int ctIndex = -1; String origCt = "";
            for (int i = 0; i < baseHeaders.size(); i++) {
                if (baseHeaders.get(i).toLowerCase().startsWith("content-type:")) { ctIndex = i; origCt = baseHeaders.get(i); break; }
            }
            if (ctIndex != -1) {
                String[] spoofTypes = {"application/xml", "application/x-www-form-urlencoded", origCt + ";charset=ibm037"};
                for(String st : spoofTypes) {
                    try {
                        List<String> newHeaders = new ArrayList<>(baseHeaders);
                        newHeaders.set(ctIndex, "Content-Type: " + st);
                        runner.run("Content-Type", st, ext.callbacks.getHelpers().buildHttpMessage(newHeaders, baseBody));
                    } catch (Exception ignored) {}
                }
            }
        }

        // 6. 靶向历史 CVE 漏洞探测
        if (modes.contains("cve")) {
            for (String cvePath : ext.cCvePayloads) {
                if (cvePath.trim().isEmpty()) continue;
                try {
                    List<String> newHeaders = new ArrayList<>(baseHeaders);
                    String firstLine = newHeaders.get(0);
                    String[] parts = firstLine.split(" ");
                    if (parts.length >= 2) {
                        String newUri = cvePath.trim();
                        if (!newUri.startsWith("/")) newUri = "/" + newUri;
                        newHeaders.set(0, parts[0] + " " + newUri + (parts.length >= 3 ? " " + parts[2] : ""));
                        runner.run("CVE", newUri, ext.callbacks.getHelpers().buildHttpMessage(newHeaders, baseBody));
                    }
                } catch (Exception ignored) {}
            }
        }

        // 7. Host 碰撞与伪造
        if (modes.contains("host")) {
            for (String spoofedHost : ext.cHostPayloads) {
                if (spoofedHost.trim().isEmpty()) continue;
                try {
                    List<String> newHeaders = new ArrayList<>(baseHeaders);
                    for (int i = 0; i < newHeaders.size(); i++) {
                        if (newHeaders.get(i).toLowerCase().startsWith("host:")) {
                            newHeaders.set(i, "Host: " + spoofedHost.trim()); break;
                        }
                    }
                    runner.run("Host Spoofing", spoofedHost, ext.callbacks.getHelpers().buildHttpMessage(newHeaders, baseBody));
                } catch (Exception ignored) {}
            }
        }

        // 8. HTTP 参数污染 (HPP)
        if (modes.contains("hpp")) {
            for (String hppPayload : ext.cHppPayloads) {
                if (hppPayload.trim().isEmpty()) continue;
                try {
                    List<String> newHeaders = new ArrayList<>(baseHeaders);
                    String firstLine = newHeaders.get(0);
                    String[] parts = firstLine.split(" ");
                    if (parts.length >= 2) {
                        String originalUri = parts[1];
                        String sep = originalUri.contains("?") ? "&" : "?";
                        String newUri = originalUri + sep + hppPayload.trim();
                        newHeaders.set(0, parts[0] + " " + newUri + (parts.length >= 3 ? " " + parts[2] : ""));
                        runner.run("HPP", hppPayload, ext.callbacks.getHelpers().buildHttpMessage(newHeaders, baseBody));
                    }
                } catch (Exception ignored) {}
            }
        }
    }

    public List<String> generatePermutations(String path, String payload) {
        Set<String> set = new java.util.LinkedHashSet<>(); // 使用 Set 自动去重
        if (path == null || path.isEmpty()) path = "/";
        if (!path.startsWith("/")) path = "/" + path;

        // 1. 尾部追加 (最高频绕过点，例如: /api/admin -> /api/admin/..;/ 或 /api/admin.json)
        set.add(path + payload);
        if (!payload.startsWith(".") && !payload.startsWith(";")) {
            set.add(path + "/" + payload);
        }

        // 2. 头部伪装 (针对反向代理/网关配置失误，例如: /api/admin -> /;/api/admin)
        set.add("/" + payload + path);

        // 3. 最后一层目录阻断 (针对 Spring Boot / Tomcat 越权，例如: /api/v1/user -> /api/v1/..;/user)
        int lastSlash = path.lastIndexOf('/');
        if (lastSlash > 0) { // 确保不是根路径 "/"
            String before = path.substring(0, lastSlash);
            String after = path.substring(lastSlash + 1);

            // 将 Payload 插入到最后一级真实端点的前面
            set.add(before + "/" + payload + "/" + after);
            // 应对有些 WAF 过滤连续斜杠的情况
            set.add(before + payload + "/" + after);
        }

        return new ArrayList<>(set);
    }
}
