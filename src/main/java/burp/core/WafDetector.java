package burp.core;

import burp.BurpExtender;
import burp.IResponseInfo;
import burp.models.WafProfile;

import javax.swing.*;
import java.awt.*;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

public class WafDetector {
    private final BurpExtender ext;

    public WafDetector(BurpExtender ext) {
        this.ext = ext;
    }

    public String detectWAF(byte[] responseBytes) {
        if (responseBytes == null || !ext.cEnableWafDetect) return null;
        try {
            IResponseInfo info = ext.callbacks.getHelpers().analyzeResponse(responseBytes);
            int statusCode = info.getStatusCode();

            // 1. 提取原始响应 (保留 Header 的英文原始特征)
            String rawStr = ext.callbacks.getHelpers().bytesToString(responseBytes);

            // 2. 提取 Body 并强制 UTF-8 解码 (核心修复：解决中文正则失效问题)
            byte[] bodyBytes = Arrays.copyOfRange(responseBytes, info.getBodyOffset(), responseBytes.length);
            String utf8Body = new String(bodyBytes, StandardCharsets.UTF_8);

            // 将两者拼接，确保 Header 和中文 Body 都能被正则引擎搜索到
            String searchTarget = rawStr + "\n" + utf8Body;

            // 3. 严格按照顺序遍历指纹库 (已知 WAF 优先)
            for (Map.Entry<String, Pattern> entry : ext.cWafPatterns.entrySet()) {
                if (entry.getValue().matcher(searchTarget).find()) {
                    return entry.getKey();
                }
            }

            // 4. 终极兜底：未知自研 WAF 识别机制 (防漏网之鱼)
            // 很多厂商或者自研 WAF 喜欢用 418, 493 等非标准状态码直接拦截
            if (statusCode == 418 || statusCode == 493) {
                return "未知 WAF (异常拦截状态码:" + statusCode + ")";
            }

        } catch (Exception e) {}
        return null;
    }

    public void showBlacklistedPoCsDialog(String host, Set<String> pocs) {
        JDialog dialog = new JDialog(SwingUtilities.getWindowAncestor(ext.mainPanel), "拦截详情 - " + host, Dialog.ModalityType.APPLICATION_MODAL);
        dialog.setSize(500, 350);
        dialog.setLocationRelativeTo(ext.mainPanel);
        dialog.setLayout(new BorderLayout(5, 5));

        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        topPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 0, 5));
        JLabel lblInfo = new JLabel("<html>以下 Payload 已被 WAF 拦截并动态拉黑<br>插件在后续扫描该站点时已自动跳过这些测试，防封 IP：</html>");
        lblInfo.setForeground(new Color(200, 50, 0));
        topPanel.add(lblInfo);

        JTextArea textArea = new JTextArea();
        textArea.setEditable(false);
        textArea.setFont(new Font("Monospaced", Font.PLAIN, 13));
        textArea.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

        if (pocs == null || pocs.isEmpty()) {
            textArea.setText("暂无被拉黑的 PoC。");
        } else {
            int count = 1;
            for (String poc : pocs) {
                textArea.append(count + ". " + poc + "\n");
                count++;
            }
        }

        dialog.add(topPanel, BorderLayout.NORTH);
        dialog.add(new JScrollPane(textArea), BorderLayout.CENTER);

        JPanel botPanel = new JPanel();
        JButton btnClose = new JButton("关闭 (Close)");
        btnClose.addActionListener(e -> dialog.dispose());
        botPanel.add(btnClose);
        dialog.add(botPanel, BorderLayout.SOUTH);

        dialog.setVisible(true);
    }

    public void updateWafUI(String host) {
        SwingUtilities.invokeLater(() -> {
            WafProfile profile = ext.wafMap.get(host);
            if (profile == null) return;

            boolean found = false;
            for (int i = 0; i < ext.wafTableModel.getRowCount(); i++) {
                if (ext.wafTableModel.getValueAt(i, 0).equals(host)) {
                    ext.wafTableModel.setValueAt(profile.isIpBanned ? "[危险] 已被墙" : "正常", i, 2);
                    ext.wafTableModel.setValueAt(profile.blacklistedPoCs.size(), i, 3);
                    found = true;
                    break;
                }
            }
            if (!found) {
                ext.wafTableModel.addRow(new Object[]{host, profile.wafName, profile.isIpBanned ? "[危险] 已被墙" : "正常", profile.blacklistedPoCs.size()});
            }
        });
    }
}
