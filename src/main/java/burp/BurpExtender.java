package burp;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.util.List;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.StringJoiner;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;

public class BurpExtender implements IBurpExtender, ITab, IHttpListener, IContextMenuFactory {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private final String extensionName = "403 Bypasser Pro (WAF智能完整版)";

    private JPanel mainPanel;
    private JTabbedPane tabs;

    // --- UI 组件 ---
    private DefaultTableModel urlTableModel, payloadTableModel, wafTableModel;
    private JTable urlTable, payloadTable, wafTable;
    private IMessageEditor requestViewer, responseViewer;
    private JTable queryTable, headerTable, methodTable, excludeTable, whitelistTable, regexTable, wafFingerprintTable;

    private JCheckBox chkEnableAutoScan, chkEnableWhitelist;
    private JCheckBox chkProxy, chkRepeater, chkIntruder;
    private JCheckBox chkScanQuery, chkScanHeader, chkScanMethod;
    private JTextField txtStatusCodes, txtRegex;
    private JCheckBox chkEnableRegex;

    // WAF 专属控制开关
    private JCheckBox chkEnableWafDetect, chkEnableDynamicBlacklist, chkEnableIpBanCheck;

    // --- 高并发数据存储区 ---
    private final List<ScanTask> scanTasks = new CopyOnWriteArrayList<>();
    private final Set<String> dedupCache = ConcurrentHashMap.newKeySet();
    private IHttpRequestResponse currentlyDisplayedItem;
    private final AtomicInteger taskCounter = new AtomicInteger(1);
    private final ExecutorService executor = Executors.newFixedThreadPool(15);
    private File configDir;

    // --- 线程安全的后台读取缓存 (Volatile 保证多线程可见性) ---
    private volatile boolean cAutoScan;
    private volatile boolean cWhitelistOnly;
    private volatile boolean cProxy, cRepeater, cIntruder;
    private volatile boolean cScanQuery, cScanHeader, cScanMethod;
    private volatile String cStatusCodes = "401, 403, 404";
    private volatile boolean cEnableRegex, cEnableWafDetect, cEnableDynamicBlacklist, cEnableIpBanCheck;
    private volatile Pattern cRegexPattern = null;

    private volatile List<String> cQueryPayloads = new ArrayList<>();
    private volatile List<String> cHeaderPayloads = new ArrayList<>();
    private volatile List<String> cMethodPayloads = new ArrayList<>();
    private volatile List<String> cExcludeExts = new ArrayList<>();
    private volatile List<String> cWhitelist = new ArrayList<>();
    private volatile List<String> cRegexKeywords = new ArrayList<>();
    private volatile Map<String, Pattern> cWafPatterns = new LinkedHashMap<>();

    // --- 默认字典库 ---
    private final List<String> defaultQueryPayloads = Arrays.asList(
            "/", "/*", "//", "/./", "/../", "..;/", "/..;/", "/..%3b/", "%3b", ";",
            ";%09", ";%09..", ";%09..;", "%00", "%09", "%20", "%23", "%2e", "%2f",
            "%252e", "%252f", "%2e%2e%2f", "..%2f", ".json", ".xml", ".html",
            "..%00/", "..%0d/", "..%5c", "..%ff/", "%2e%2e%3b/", "*", "/%20",
            "/%2e/", "/%2e%2e/", "/;/;"
    );
    private final List<String> defaultHeaderPayloads = Arrays.asList(
            "Client-IP: 127.0.0.1", "X-Real-Ip: 127.0.0.1", "Redirect: 127.0.0.1",
            "Referer: 127.0.0.1", "X-Client-IP: 127.0.0.1", "X-Custom-IP-Authorization: 127.0.0.1",
            "X-Forwarded-By: 127.0.0.1", "X-Forwarded-For: 127.0.0.1", "X-Forwarded-Host: 127.0.0.1",
            "X-Forwarded-Port: 80", "X-True-IP: 127.0.0.1", "X-Originating-IP: 127.0.0.1",
            "X-Remote-IP: 127.0.0.1", "X-Remote-Addr: 127.0.0.1", "X-Host: 127.0.0.1",
            "X-Original-URL: /", "X-Rewrite-URL: /", "True-Client-IP: 127.0.0.1",
            "X-Forwarded-Server: 127.0.0.1", "X-HTTP-Host-Override: 127.0.0.1", "X-Wap-Profile: 127.0.0.1"
    );
    private final List<String> defaultMethodPayloads = Arrays.asList(
            "GET -> POST", "POST -> GET", "HTTP/1.1 -> HTTP/1.0",
            "GET -> OPTIONS", "GET -> TRACE", "GET -> HEAD", "GET -> PUT", "POST -> PUT"
    );
    private final List<String> defaultExcludeExts = Arrays.asList(
            ".jpg", ".jpeg", ".png", ".gif", ".css", ".js", ".woff", ".woff2", ".ico",
            ".svg", ".ttf", ".eot", ".mp4", ".mp3", ".avi", ".ts", ".vue"
    );
    private final List<String> defaultWhitelist = Arrays.asList(
            "example.com", "test"
    );
    private final List<String> defaultRegexKeywords = Arrays.asList(
            "未授权", "无权限", "权限不足", "拒绝访问", "非法请求", "拦截", "验证失败",
            "登录已过期", "登录超时", "请先登录", "未登录", "签名错误", "无效的token",
            "access denied", "unauthorized", "invalid token", "token expired",
            "not login", "forbidden", "block", "waf", "illegal", "please login",
            "authentication failed", "missing authorization"
    );
    private final List<String> defaultWafFingerprints = Arrays.asList(
            "Cloudflare: (?i)(Server: cloudflare|cf-ray:|cloudflare-nginx)",
            "阿里云盾: (?i)(errors\\.aliyun\\.com|yundun|Server: AliyunOS)",
            "腾讯云WAF: (?i)(TencentWAF)",
            "长亭SafeLine: (?i)(safeline)",
            "安全狗: (?i)(WAF/2\\.0|Safedog|safedog-flow-item)",
            "Imperva: (?i)(Server: imperva|X-Iinfo|incap_ses)",
            "AWS WAF: (?i)(x-amz-cf-id|Server: awselb)",
            "Akamai: (?i)(Server: AkamaiGHost)",
            "F5 BIG-IP: (?i)(Server: BigIP|F5-TrafficShield)",
            "360奇安信: (?i)(wangzhan\\.360\\.cn|X-Powered-By-360WZB)",
            "创宇盾: (?i)(X-Cache: jiasule|ks-waf)",
            "ModSecurity: (?i)(Mod_Security|NOYB)"
    );

    // --- WAF 智能引擎数据结构 ---
    static class WafProfile {
        String wafName;
        boolean isIpBanned = false;
        Set<String> blacklistedPoCs = ConcurrentHashMap.newKeySet();
    }
    private final Map<String, WafProfile> wafMap = new ConcurrentHashMap<>();

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName(extensionName);

        // ================= 1. 打印专属启动 Logo =================
        callbacks.printOutput("####################################################");
        callbacks.printOutput("  403 Bypasser Pro v1.2");
        callbacks.printOutput("  Author:  DLtest007");
        callbacks.printOutput("  Github:  https://github.com/DLtest007/403Bypasser-Pro");
        callbacks.printOutput("####################################################\n");

        // ================= 2. 初始化本地配置目录 =================
        // 注意：全局只声明一次 String userHome
        String userHome = System.getProperty("user.home");
        configDir = new File(userHome, ".403bypasser");
        if (!configDir.exists()) {
            configDir.mkdirs();
        }

        // ================= 3. 启动 UI 与注册监听器 =================
        SwingUtilities.invokeLater(this::initUI);
        callbacks.registerHttpListener(this);
        callbacks.registerContextMenuFactory(this);
    }

    private void initUI() {
        mainPanel = new JPanel(new BorderLayout());
        tabs = new JTabbedPane();

        // ====== 1. 扫描大盘 (Dashboard Tab) ======
        JPanel dashboardPanel = new JPanel(new BorderLayout());
        JSplitPane rootSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        JSplitPane dataSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        JSplitPane topSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);

        // --- URL Table ---
        urlTableModel = new DefaultTableModel(new String[]{"#", "方法", "URL", "原始 Body 长度"}, 0) {
            @Override public Class<?> getColumnClass(int column) { return (column == 0 || column == 3) ? Integer.class : String.class; }
            @Override public boolean isCellEditable(int row, int column) { return false; }
        };
        urlTable = new JTable(urlTableModel);
        urlTable.setRowSorter(new TableRowSorter<>(urlTableModel));
        urlTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        urlTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting() && urlTable.getSelectedRow() != -1) {
                payloadTableModel.setRowCount(0);
                int modelRow = urlTable.convertRowIndexToModel(urlTable.getSelectedRow());
                ScanTask task = scanTasks.get(modelRow);
                for (PayloadResult pr : task.results) {
                    payloadTableModel.addRow(new Object[]{pr.type, pr.payload, pr.newLen, pr.diff, pr.timeMs, pr.status});
                }
            }
        });
        urlTable.getColumnModel().getColumn(0).setPreferredWidth(40);
        urlTable.getColumnModel().getColumn(1).setPreferredWidth(60);
        urlTable.getColumnModel().getColumn(2).setPreferredWidth(300);

        // --- Payload Table ---
        payloadTableModel = new DefaultTableModel(new String[]{"类型", "Payload", "新 Body 长度", "差异 (Diff)", "用时 (ms)", "状态码"}, 0) {
            @Override public Class<?> getColumnClass(int column) { return column >= 2 ? Integer.class : String.class; }
            @Override public boolean isCellEditable(int row, int column) { return false; }
        };
        payloadTable = new JTable(payloadTableModel);
        payloadTable.setRowSorter(new TableRowSorter<>(payloadTableModel));

        payloadTable.getColumnModel().getColumn(3).setCellRenderer(new DefaultTableCellRenderer() {
            @Override protected void setValue(Object value) {
                if (value instanceof Integer) {
                    int diff = (Integer) value;
                    setText(diff > 0 ? "+" + diff : String.valueOf(diff));
                    if(diff != 0) {
                        setForeground(new Color(200, 50, 50));
                        setFont(getFont().deriveFont(Font.BOLD));
                    } else {
                        setForeground(Color.BLACK);
                        setFont(getFont().deriveFont(Font.PLAIN));
                    }
                } else { super.setValue(value); }
            }
        });

        payloadTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        payloadTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting() && urlTable.getSelectedRow() != -1 && payloadTable.getSelectedRow() != -1) {
                int uRow = urlTable.convertRowIndexToModel(urlTable.getSelectedRow());
                int pRow = payloadTable.convertRowIndexToModel(payloadTable.getSelectedRow());
                ScanTask task = scanTasks.get(uRow);
                PayloadResult pr = task.results.get(pRow);
                currentlyDisplayedItem = pr.reqRes;
                requestViewer.setMessage(pr.reqRes.getRequest(), true);
                responseViewer.setMessage(pr.reqRes.getResponse() != null ? pr.reqRes.getResponse() : new byte[0], false);
            }
        });
        payloadTable.getColumnModel().getColumn(1).setPreferredWidth(200);

        JPanel urlPanel = new JPanel(new BorderLayout(0, 5));
        JLabel lblUrl = new JLabel(" 已扫描接口 (Scanned Interfaces)");
        lblUrl.setFont(lblUrl.getFont().deriveFont(Font.BOLD));
        urlPanel.add(lblUrl, BorderLayout.NORTH);
        urlPanel.add(new JScrollPane(urlTable), BorderLayout.CENTER);

        JPanel payloadPanel = new JPanel(new BorderLayout(0, 5));
        JLabel lblPayload = new JLabel(" 测试结果 (Payload Results)");
        lblPayload.setFont(lblPayload.getFont().deriveFont(Font.BOLD));
        payloadPanel.add(lblPayload, BorderLayout.NORTH);
        payloadPanel.add(new JScrollPane(payloadTable), BorderLayout.CENTER);

        topSplit.setLeftComponent(urlPanel);
        topSplit.setRightComponent(payloadPanel);
        topSplit.setResizeWeight(0.4);

        IMessageEditorController controller = new IMessageEditorController() {
            public IHttpService getHttpService() { return currentlyDisplayedItem != null ? currentlyDisplayedItem.getHttpService() : null; }
            public byte[] getRequest() { return currentlyDisplayedItem != null ? currentlyDisplayedItem.getRequest() : null; }
            public byte[] getResponse() { return currentlyDisplayedItem != null ? currentlyDisplayedItem.getResponse() : null; }
        };
        requestViewer = callbacks.createMessageEditor(controller, false);
        responseViewer = callbacks.createMessageEditor(controller, false);

        JSplitPane viewerSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        JPanel reqPanel = new JPanel(new BorderLayout(0, 5));
        JLabel lblReq = new JLabel(" 请求包 (Request)");
        lblReq.setFont(lblReq.getFont().deriveFont(Font.BOLD));
        reqPanel.add(lblReq, BorderLayout.NORTH);
        reqPanel.add(requestViewer.getComponent(), BorderLayout.CENTER);

        JPanel resPanel = new JPanel(new BorderLayout(0, 5));
        JLabel lblRes = new JLabel(" 响应包 (Response)");
        lblRes.setFont(lblRes.getFont().deriveFont(Font.BOLD));
        resPanel.add(lblRes, BorderLayout.NORTH);
        resPanel.add(responseViewer.getComponent(), BorderLayout.CENTER);

        viewerSplit.setLeftComponent(reqPanel);
        viewerSplit.setRightComponent(resPanel);
        viewerSplit.setResizeWeight(0.5);

        dataSplit.setTopComponent(topSplit);
        dataSplit.setBottomComponent(viewerSplit);
        dataSplit.setResizeWeight(0.5);

        // --- 控制面板 (Control Panel) ---
        JPanel ctrlPanel = new JPanel();
        ctrlPanel.setLayout(new BoxLayout(ctrlPanel, BoxLayout.Y_AXIS));
        ctrlPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JLabel lblCtrlTitle = new JLabel("▼ 1. 全局与白名单");
        lblCtrlTitle.setFont(lblCtrlTitle.getFont().deriveFont(Font.BOLD, 13f));
        ctrlPanel.add(lblCtrlTitle);
        chkEnableAutoScan = new JCheckBox("允许被动监听与扫描", false);
        chkEnableAutoScan.setForeground(new Color(200, 0, 0));
        ctrlPanel.add(chkEnableAutoScan);
        chkEnableWhitelist = new JCheckBox("开启白名单匹配 (推荐)", false);
        ctrlPanel.add(chkEnableWhitelist);

        ctrlPanel.add(Box.createVerticalStrut(10));
        JLabel lblMon = new JLabel("▼ 2. 抓取模块来源");
        lblMon.setFont(lblMon.getFont().deriveFont(Font.BOLD, 13f));
        ctrlPanel.add(lblMon);
        chkProxy = new JCheckBox("代理 (Proxy)", true); ctrlPanel.add(chkProxy);
        chkRepeater = new JCheckBox("重放器 (Repeater)", true); ctrlPanel.add(chkRepeater);
        chkIntruder = new JCheckBox("Intruder", false); ctrlPanel.add(chkIntruder);

        ctrlPanel.add(Box.createVerticalStrut(10));
        JLabel lblEnabled = new JLabel("▼ 3. 扫描字典开启配置");
        lblEnabled.setFont(lblEnabled.getFont().deriveFont(Font.BOLD, 13f));
        ctrlPanel.add(lblEnabled);
        chkScanQuery = new JCheckBox("路径字典 Fuzz (Query)", true); ctrlPanel.add(chkScanQuery);
        chkScanHeader = new JCheckBox("请求头绕过 (Header)", true); ctrlPanel.add(chkScanHeader);
        chkScanMethod = new JCheckBox("动词篡改降级 (Method)", true); ctrlPanel.add(chkScanMethod);

        ctrlPanel.add(Box.createVerticalStrut(10));
        JLabel lblWaf = new JLabel("▼ 4. WAF 智能防御对抗机制");
        lblWaf.setFont(lblWaf.getFont().deriveFont(Font.BOLD, 13f));
        ctrlPanel.add(lblWaf);
        chkEnableWafDetect = new JCheckBox("启用 WAF 识别与拦截接管", true);
        chkEnableWafDetect.setForeground(new Color(200, 50, 0));
        ctrlPanel.add(chkEnableWafDetect);
        chkEnableDynamicBlacklist = new JCheckBox("启用 PoC 动态拉黑 (防墙)", true);
        ctrlPanel.add(chkEnableDynamicBlacklist);
        chkEnableIpBanCheck = new JCheckBox("启用 IP 封禁智能探活验证", true);
        ctrlPanel.add(chkEnableIpBanCheck);

        ctrlPanel.add(Box.createVerticalStrut(10));
        JLabel lblTrig = new JLabel("▼ 5. 扫描触发条件");
        lblTrig.setFont(lblTrig.getFont().deriveFont(Font.BOLD, 13f));
        ctrlPanel.add(lblTrig);
        ctrlPanel.add(new JLabel("目标状态码 (用逗号分隔):"));
        txtStatusCodes = new JTextField("401, 403, 404");
        txtStatusCodes.setMaximumSize(new Dimension(250, 30));
        ctrlPanel.add(txtStatusCodes);
        ctrlPanel.add(Box.createVerticalStrut(5));
        chkEnableRegex = new JCheckBox("启用假200伪装抓取", true);
        ctrlPanel.add(chkEnableRegex);

        ctrlPanel.add(Box.createVerticalStrut(15));
        JLabel lblData = new JLabel("▼ 6. 数据管理");
        lblData.setFont(lblData.getFont().deriveFont(Font.BOLD, 13f));
        ctrlPanel.add(lblData);
        JButton btnClearCache = new JButton("清空去重缓存 (可重扫老接口)");
        btnClearCache.addActionListener(e -> {
            dedupCache.clear();
            callbacks.printOutput("[*] 去重缓存已清空！");
        });
        ctrlPanel.add(btnClearCache);
        ctrlPanel.add(Box.createVerticalStrut(5));
        JButton btnClearData = new JButton("清空所有扫描与WAF缓存");
        btnClearData.addActionListener(e -> {
            scanTasks.clear(); urlTableModel.setRowCount(0); payloadTableModel.setRowCount(0);
            dedupCache.clear(); wafMap.clear(); wafTableModel.setRowCount(0); taskCounter.set(1);
            requestViewer.setMessage(new byte[0], true); responseViewer.setMessage(new byte[0], false);
            callbacks.printOutput("[*] 所有缓存已完全重置！");
        });
        ctrlPanel.add(btnClearData);

        rootSplit.setLeftComponent(dataSplit);
        rootSplit.setRightComponent(ctrlPanel);
        rootSplit.setResizeWeight(0.85);
        dashboardPanel.add(rootSplit, BorderLayout.CENTER);

        // ====== 2. WAF 情报中心 Tab ======
        JPanel wafPanel = new JPanel(new BorderLayout(5, 5));
        wafPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        wafTableModel = new DefaultTableModel(new String[]{"目标站点 (Host)", "识别的 WAF 指纹", "IP 被墙状态", "被动态拉黑的 PoC 数量"}, 0) {
            @Override public boolean isCellEditable(int row, int column) { return false; }
        };
        wafTable = new JTable(wafTableModel);
        wafTable.setRowSorter(new TableRowSorter<>(wafTableModel));
        wafTable.getColumnModel().getColumn(2).setCellRenderer(new DefaultTableCellRenderer() {
            @Override protected void setValue(Object value) {
                setText(value != null ? value.toString() : "");
                if ("[危险] 已被墙".equals(value)) {
                    setForeground(Color.RED); setFont(getFont().deriveFont(Font.BOLD));
                } else {
                    setForeground(new Color(0, 150, 0)); setFont(getFont().deriveFont(Font.PLAIN));
                }
            }
        });
        JLabel lblWafCenter = new JLabel(" WAF 动态识别与拦截记录库");
        lblWafCenter.setFont(lblWafCenter.getFont().deriveFont(Font.BOLD));
        wafPanel.add(lblWafCenter, BorderLayout.NORTH);
        wafPanel.add(new JScrollPane(wafTable), BorderLayout.CENTER);

        // ====== 3. 配置中心 (Configuration Panel) 4x2 网格 ======
        JPanel configPanel = new JPanel(new GridLayout(4, 2, 10, 10));
        queryTable = buildConfigModule(configPanel, "路径与参数畸变 (Query)", "bypasser_query.txt", defaultQueryPayloads);
        headerTable = buildConfigModule(configPanel, "请求头越权与伪造 (Header)", "bypasser_header.txt", defaultHeaderPayloads);
        methodTable = buildConfigModule(configPanel, "动词篡改与协议转换 (Method)", "bypasser_method.txt", defaultMethodPayloads);
        excludeTable = buildConfigModule(configPanel, "静态资源放行 (Exclude Exts)", "bypasser_ext.txt", defaultExcludeExts);
        whitelistTable = buildConfigModule(configPanel, "域名白名单关键字 (Whitelist)", "bypasser_whitelist.txt", defaultWhitelist);
        regexTable = buildConfigModule(configPanel, "假200匹配特征 (Regex Keywords)", "bypasser_regex.txt", defaultRegexKeywords);
        wafFingerprintTable = buildConfigModule(configPanel, "自定义WAF指纹库 (格式 Name:Regex)", "bypasser_waf.txt", defaultWafFingerprints);

        // 最后一个格子显示帮助说明
        JPanel helpPanel = new JPanel(new BorderLayout());
        helpPanel.setBorder(BorderFactory.createTitledBorder("字典编写指南"));
        JTextArea helpText = new JTextArea(
                "1. 假200正则：支持填入任意中文或特殊字符（如 {\"code\":-1}），程序自动安全转义。\n\n" +
                        "2. WAF指纹库：必须严格按照 [名称:正则表达式] 格式填写。\n" +
                        "   例如 -> Cloudflare: (?i)(cf-ray|cloudflare)\n\n" +
                        "3. 所有字典修改完毕后，离开输入框或敲击回车，即可瞬间热加载至内存，无需重启插件。"
        );
        helpText.setEditable(false);
        helpText.setBackground(helpPanel.getBackground());
        helpText.setFont(helpText.getFont().deriveFont(12f));
        helpPanel.add(new JScrollPane(helpText), BorderLayout.CENTER);
        configPanel.add(helpPanel);

        tabs.addTab("扫描大盘 (Dashboard)", dashboardPanel);
        tabs.addTab("WAF 拦截情报中心", wafPanel);
        tabs.addTab("配置中心 (Configuration)", configPanel);

        JPanel bottomInfoPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel infoLabel = new JLabel(" 配置文件保存在: " + configDir.getAbsolutePath() + " | (实时多线程内存隔离同步已开启)");
        infoLabel.setForeground(Color.GRAY);
        bottomInfoPanel.add(infoLabel);

        mainPanel.add(tabs, BorderLayout.CENTER);
        mainPanel.add(bottomInfoPanel, BorderLayout.SOUTH);

        callbacks.addSuiteTab(this);

        updateCachesFromUI();
        setupCacheSyncListeners();
    }

    private void setupCacheSyncListeners() {
        ActionListener syncAction = e -> updateCachesFromUI();
        chkEnableAutoScan.addActionListener(syncAction);
        chkEnableWhitelist.addActionListener(syncAction);
        chkProxy.addActionListener(syncAction);
        chkRepeater.addActionListener(syncAction);
        chkIntruder.addActionListener(syncAction);
        chkScanQuery.addActionListener(syncAction);
        chkScanHeader.addActionListener(syncAction);
        chkScanMethod.addActionListener(syncAction);
        chkEnableRegex.addActionListener(syncAction);
        chkEnableWafDetect.addActionListener(syncAction);
        chkEnableDynamicBlacklist.addActionListener(syncAction);
        chkEnableIpBanCheck.addActionListener(syncAction);

        DocumentListener docSync = new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e) { updateCachesFromUI(); }
            @Override public void removeUpdate(DocumentEvent e) { updateCachesFromUI(); }
            @Override public void changedUpdate(DocumentEvent e) { updateCachesFromUI(); }
        };
        txtStatusCodes.getDocument().addDocumentListener(docSync);
    }

    private void updateCachesFromUI() {
        SwingUtilities.invokeLater(() -> {
            if (whitelistTable.isEditing()) whitelistTable.getCellEditor().stopCellEditing();
            if (queryTable.isEditing()) queryTable.getCellEditor().stopCellEditing();
            if (headerTable.isEditing()) headerTable.getCellEditor().stopCellEditing();
            if (methodTable.isEditing()) methodTable.getCellEditor().stopCellEditing();
            if (excludeTable.isEditing()) excludeTable.getCellEditor().stopCellEditing();
            if (regexTable.isEditing()) regexTable.getCellEditor().stopCellEditing();
            if (wafFingerprintTable.isEditing()) wafFingerprintTable.getCellEditor().stopCellEditing();

            cAutoScan = chkEnableAutoScan.isSelected();
            cWhitelistOnly = chkEnableWhitelist.isSelected();
            cProxy = chkProxy.isSelected();
            cRepeater = chkRepeater.isSelected();
            cIntruder = chkIntruder.isSelected();
            cScanQuery = chkScanQuery.isSelected();
            cScanHeader = chkScanHeader.isSelected();
            cScanMethod = chkScanMethod.isSelected();
            cStatusCodes = txtStatusCodes.getText();
            cEnableRegex = chkEnableRegex.isSelected();

            cEnableWafDetect = chkEnableWafDetect.isSelected();
            cEnableDynamicBlacklist = chkEnableDynamicBlacklist.isSelected();
            cEnableIpBanCheck = chkEnableIpBanCheck.isSelected();

            cQueryPayloads = getTableData(queryTable);
            cHeaderPayloads = getTableData(headerTable);
            cMethodPayloads = getTableData(methodTable);
            cExcludeExts = getTableData(excludeTable);
            cWhitelist = getTableData(whitelistTable);
            cRegexKeywords = getTableData(regexTable);

            // 1. 动态编译假 200 正则引擎
            if (cEnableRegex && !cRegexKeywords.isEmpty()) {
                StringJoiner sj = new StringJoiner("|");
                for (String kw : cRegexKeywords) {
                    if (!kw.trim().isEmpty()) sj.add(Pattern.quote(kw.trim()));
                }
                cRegexPattern = sj.length() > 0 ? Pattern.compile("(?i)(" + sj.toString() + ")") : null;
            } else {
                cRegexPattern = null;
            }

            // 2. 动态编译 WAF 指纹库引擎
            Map<String, Pattern> tempWafPatterns = new LinkedHashMap<>();
            for (String line : getTableData(wafFingerprintTable)) {
                int idx = line.indexOf(":");
                if (idx > 0) {
                    String name = line.substring(0, idx).trim();
                    String reg = line.substring(idx + 1).trim();
                    try {
                        tempWafPatterns.put(name, Pattern.compile(reg));
                    } catch (Exception ex) {
                        callbacks.printError("[!] WAF 正则编译失败, 已跳过 [" + name + "]: " + ex.getMessage());
                    }
                }
            }
            cWafPatterns = tempWafPatterns;
        });
    }

    private JTable buildConfigModule(JPanel parent, String title, String filename, List<String> defaultData) {
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        JLabel lblTitle = new JLabel(title);
        lblTitle.setFont(lblTitle.getFont().deriveFont(Font.BOLD));
        panel.add(lblTitle, BorderLayout.NORTH);

        File file = new File(configDir, filename);
        List<String> data = defaultData;
        if (!file.exists()) {
            try { Files.write(file.toPath(), defaultData); } catch (IOException ignored) {}
        } else {
            try { data = Files.readAllLines(file.toPath()); } catch (IOException ignored) {}
        }

        DefaultTableModel model = new DefaultTableModel(new String[]{title}, 0);
        for (String item : data) {
            if (!item.trim().isEmpty()) model.addRow(new Object[]{item.trim()});
        }
        JTable table = new JTable(model);

        // 绑定数据改动监听器，确保双击编辑后自动保存并同步内存
        model.addTableModelListener(e -> saveConfig(table, file));

        panel.add(new JScrollPane(table), BorderLayout.CENTER);

        JPanel bot = new JPanel(new BorderLayout(5, 5));
        JTextField txt = new JTextField();
        JPanel btns = new JPanel(new GridLayout(1, 3, 5, 5));

        JButton btnAdd = new JButton("添加");
        btnAdd.addActionListener(e -> {
            if (!txt.getText().isEmpty()) {
                model.addRow(new Object[]{txt.getText()});
                txt.setText("");
            }
        });
        txt.addActionListener(e -> btnAdd.doClick()); // 回车一键添加

        JButton btnClear = new JButton("清空");
        btnClear.addActionListener(e -> model.setRowCount(0));

        JButton btnRemove = new JButton("删除");
        btnRemove.addActionListener(e -> {
            int[] rows = table.getSelectedRows();
            for (int i = rows.length - 1; i >= 0; i--) {
                model.removeRow(rows[i]);
            }
        });

        btns.add(btnAdd); btns.add(btnClear); btns.add(btnRemove);
        bot.add(txt, BorderLayout.CENTER);
        bot.add(btns, BorderLayout.SOUTH);
        panel.add(bot, BorderLayout.SOUTH);

        parent.add(panel);
        return table;
    }

    private void saveConfig(JTable table, File file) {
        try {
            List<String> lines = new ArrayList<>();
            for (int i = 0; i < table.getRowCount(); i++) {
                lines.add(table.getValueAt(i, 0).toString());
            }
            Files.write(file.toPath(), lines);
        } catch (IOException e) {
            callbacks.printError("文件写入失败: " + e.getMessage());
        } finally {
            updateCachesFromUI(); // 确保不管写文件成不成功，内存必须同步
        }
    }

    private List<String> getTableData(JTable table) {
        List<String> list = new ArrayList<>();
        for (int i = 0; i < table.getRowCount(); i++) {
            list.add(table.getValueAt(i, 0).toString());
        }
        return list;
    }

    // --- WAF 核心识别与探针逻辑 ---
    private String detectWAF(byte[] responseBytes) {
        if (responseBytes == null || !cEnableWafDetect) return null;
        try {
            String respStr = helpers.bytesToString(responseBytes);
            for (Map.Entry<String, Pattern> entry : cWafPatterns.entrySet()) {
                if (entry.getValue().matcher(respStr).find()) {
                    return entry.getKey();
                }
            }
        } catch (Exception e) {}
        return null;
    }

    private void updateWafUI(String host) {
        SwingUtilities.invokeLater(() -> {
            WafProfile profile = wafMap.get(host);
            if (profile == null) return;

            boolean found = false;
            for (int i = 0; i < wafTableModel.getRowCount(); i++) {
                if (wafTableModel.getValueAt(i, 0).equals(host)) {
                    wafTableModel.setValueAt(profile.isIpBanned ? "[危险] 已被墙" : "正常", i, 2);
                    wafTableModel.setValueAt(profile.blacklistedPoCs.size(), i, 3);
                    found = true;
                    break;
                }
            }
            if (!found) {
                wafTableModel.addRow(new Object[]{host, profile.wafName, profile.isIpBanned ? "[危险] 已被墙" : "正常", profile.blacklistedPoCs.size()});
            }
        });
    }

    private String cleanKeyword(String kw) {
        String s = kw.trim().toLowerCase();
        s = s.replace("http://", "").replace("https://", "");
        if (s.startsWith("*.")) s = s.substring(2);
        if (s.startsWith("*")) s = s.substring(1);
        if (s.endsWith("/")) s = s.substring(0, s.length() - 1);
        return s;
    }

    private boolean isExcluded(URL url) {
        if(url.getPath() == null) return false;
        String path = url.getPath().toLowerCase();
        for (String ext : cExcludeExts) {
            String cleanExt = ext.trim().toLowerCase();
            if (!cleanExt.isEmpty() && path.endsWith(cleanExt)) return true;
        }
        return false;
    }

    private boolean isWhitelisted(URL url) {
        if (!cWhitelistOnly) return true; // 未开启白名单时，全局放行
        if (url == null || url.getHost() == null) return false;

        String host = url.getHost().toLowerCase();
        for (String kw : cWhitelist) {
            String cleanKw = cleanKeyword(kw);
            if (!cleanKw.isEmpty() && host.contains(cleanKw)) {
                return true;
            }
        }
        callbacks.printOutput("[-] 丢弃 (未命中白名单): Host [" + host + "] 不包含你配置的任意关键字");
        return false;
    }

    private int getBodyLength(byte[] response) {
        if (response == null) return 0;
        try {
            String respStr = helpers.bytesToString(response);
            String[] parts = respStr.split("\r\n\r\n", 2);
            if (parts.length == 2) {
                return parts[1].length();
            }
            return 0;
        } catch (Exception e) {
            return 0;
        }
    }

    // --- 核心入口：被动监听 ---
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (messageIsRequest || !cAutoScan) return;

        boolean isProxy = (toolFlag == IBurpExtenderCallbacks.TOOL_PROXY);
        boolean isRepeater = (toolFlag == IBurpExtenderCallbacks.TOOL_REPEATER);
        boolean isIntruder = (toolFlag == IBurpExtenderCallbacks.TOOL_INTRUDER);

        if (!(isProxy && cProxy || isRepeater && cRepeater || isIntruder && cIntruder)) return;

        byte[] response = messageInfo.getResponse();
        if (response == null) return;

        IRequestInfo reqInfo = helpers.analyzeRequest(messageInfo);
        URL url = reqInfo.getUrl();
        if (cWhitelistOnly && !isWhitelisted(url)) return;

        // 【WAF 拦截网关】如果 IP 已被墙，直接拦截被动扫描，不再做无用功
        if (wafMap.containsKey(url.getHost()) && wafMap.get(url.getHost()).isIpBanned) {
            return;
        }

        IResponseInfo info = helpers.analyzeResponse(response);
        int statusCode = info.getStatusCode();
        boolean matched = false;

        String[] targetCodes = cStatusCodes.split(",");
        for (String code : targetCodes) {
            if (String.valueOf(statusCode).equals(code.trim())) { matched = true; break; }
        }

        if (!matched && cEnableRegex && cRegexPattern != null) {
            byte[] body = Arrays.copyOfRange(response, info.getBodyOffset(), response.length);
            String bodyStr = helpers.bytesToString(body);
            if (cRegexPattern.matcher(bodyStr).find()) matched = true;
        }

        if (matched) {
            String dedupKey = reqInfo.getMethod() + "_" + url.getHost() + url.getPath();
            if (isExcluded(url) || dedupCache.contains(dedupKey)) return;
            dedupCache.add(dedupKey);

            List<String> modes = new ArrayList<>();
            if (cScanQuery) modes.add("query");
            if (cScanHeader) modes.add("header");
            if (cScanMethod) modes.add("method");

            if (!modes.isEmpty()) {
                callbacks.printOutput("[+] 触发被动扫描: " + url.toString());
                executor.submit(() -> doScan(messageInfo, modes));
            }
        }
    }

    // --- 核心补全：右键主动扫描菜单 ---
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> list = new ArrayList<>();
        JMenu menu = new JMenu("403 Bypass (主动扫描)");

        JMenuItem itemQuery = new JMenuItem("仅扫描路径字典 (Query)");
        itemQuery.addActionListener(e -> triggerManualScan(invocation, Arrays.asList("query")));

        JMenuItem itemHeader = new JMenuItem("仅扫描请求头字典 (Header)");
        itemHeader.addActionListener(e -> triggerManualScan(invocation, Arrays.asList("header")));

        JMenuItem itemAll = new JMenuItem("全部扫描 (All)");
        itemAll.addActionListener(e -> triggerManualScan(invocation, Arrays.asList("query", "header", "method")));

        menu.add(itemQuery);
        menu.add(itemHeader);
        menu.add(itemAll);
        list.add(menu);
        return list;
    }

    private void triggerManualScan(IContextMenuInvocation invocation, List<String> modes) {
        for (IHttpRequestResponse msg : invocation.getSelectedMessages()) {
            IRequestInfo req = helpers.analyzeRequest(msg);
            dedupCache.add(req.getMethod() + "_" + req.getUrl().getHost() + req.getUrl().getPath());
            callbacks.printOutput("[+] 触发手动强制扫描: " + req.getUrl().toString());
            executor.submit(() -> doScan(msg, modes));
        }
    }

    // --- 核心扫描与 WAF 调度引擎 ---
    private void doScan(IHttpRequestResponse baseMsg, List<String> modes) {
        IHttpService service = baseMsg.getHttpService();
        byte[] origReqBytes = baseMsg.getRequest();
        IRequestInfo origReqInfo = helpers.analyzeRequest(service, origReqBytes);
        String host = origReqInfo.getUrl().getHost();

        byte[] origRespBytes = baseMsg.getResponse();
        if (origRespBytes == null) {
            try { origRespBytes = callbacks.makeHttpRequest(service, origReqBytes).getResponse(); } catch (Exception ignored) {}
        }
        int origLen = getBodyLength(origRespBytes);

        ScanTask task = new ScanTask(taskCounter.getAndIncrement(), origReqInfo.getMethod(), origReqInfo.getUrl().toString(), origLen);
        SwingUtilities.invokeLater(new AddTaskRunnable(this, task));

        List<String> baseHeaders = origReqInfo.getHeaders();
        byte[] baseBody = Arrays.copyOfRange(origReqBytes, origReqInfo.getBodyOffset(), origReqBytes.length);
        String path = origReqInfo.getUrl().getPath();
        String query = origReqInfo.getUrl().getQuery();

        // 统一的发包与 WAF 拦截处理函数
        class PayloadRunner {
            void run(String type, String payloadStr, byte[] newReq) {
                // 1. 全局 IP 封禁拦截
                WafProfile profile = wafMap.get(host);
                if (profile != null && profile.isIpBanned) return;

                // 2. 动态黑名单拦截 (如果该 PoC 已经被该站点的 WAF 拦过，直接跳过)
                if (cEnableDynamicBlacklist && profile != null && profile.blacklistedPoCs.contains(payloadStr)) {
                    return;
                }

                try {
                    long start = System.currentTimeMillis();
                    IHttpRequestResponse res = callbacks.makeHttpRequest(service, newReq);
                    long time = System.currentTimeMillis() - start;

                    if (res.getResponse() != null) {
                        int nLen = getBodyLength(res.getResponse());
                        int statusCode = helpers.analyzeResponse(res.getResponse()).getStatusCode();

                        // 3. WAF 探针逻辑
                        String wafDetected = detectWAF(res.getResponse());
                        if (wafDetected != null) {
                            if (profile == null) {
                                profile = new WafProfile();
                                profile.wafName = wafDetected;
                                wafMap.put(host, profile);
                            }

                            if (cEnableDynamicBlacklist) {
                                boolean ipBannedConfirm = false;
                                // 探活机制：如果开启了 IP 验证，补发一次原始的安全包
                                if (cEnableIpBanCheck) {
                                    IHttpRequestResponse testBase = callbacks.makeHttpRequest(service, origReqBytes);
                                    if (testBase.getResponse() != null && detectWAF(testBase.getResponse()) != null) {
                                        ipBannedConfirm = true; // 原始包也被 WAF 拦了，彻底被墙
                                    }
                                }

                                if (ipBannedConfirm) {
                                    profile.isIpBanned = true;
                                    callbacks.printOutput("[!] 危险警告: " + host + " 的 IP 已被 " + wafDetected + " 封禁！自动终止该站点的后续扫描。");
                                } else {
                                    // IP 没墙，拉黑这个惹事的 PoC
                                    profile.blacklistedPoCs.add(payloadStr);
                                    callbacks.printOutput("[-] PoC 拦截: '" + payloadStr + "' 触发了 WAF，已动态加入该站点黑名单。");
                                }
                                updateWafUI(host);
                            }
                        }

                        // 如果已经被墙了，这条垃圾数据就没必要显示在前端结果表格里了
                        if (profile != null && profile.isIpBanned) return;

                        PayloadResult pr = new PayloadResult(type, payloadStr, nLen, nLen - origLen, (int)time, statusCode, res);
                        SwingUtilities.invokeLater(new AddPayloadRunnable(BurpExtender.this, task, pr));
                    }
                } catch (Exception ignored) {}
            }
        }
        PayloadRunner runner = new PayloadRunner();

        // 1. Query 执行逻辑
        if (modes.contains("query")) {
            for (String payload : cQueryPayloads) {
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

                        // 核心修复：只在这里进行智能缩写判断，然后丢给统一的 runner 引擎去发包
                        String displayPayload = path.length() > 1 ? pTest.replace(path, "...") : pTest;
                        runner.run("Query", displayPayload, helpers.buildHttpMessage(newHeaders, baseBody));

                    } catch (Exception ignored) {}
                }
            }
        }

        // 2. Header
        if (modes.contains("header")) {
            for (String payload : cHeaderPayloads) {
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
                    runner.run("Header", payload, helpers.buildHttpMessage(newHeaders, baseBody));
                } catch (Exception ignored) {}
            }
        }

        // 3. Method
        if (modes.contains("method")) {
            for (String payload : cMethodPayloads) {
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
                        runner.run("Method", payload, helpers.buildHttpMessage(newHeaders, newBody));
                    }
                } catch (Exception ignored) {}
            }
        }
    }

    private List<String> generatePermutations(String path, String payload) {
        List<String> list = new ArrayList<>();
        int index = path.indexOf('/');
        while (index >= 0) {
            list.add(path.substring(0, index) + payload + path.substring(index));
            list.add(path.substring(0, index) + "/" + payload + path.substring(index + 1));
            list.add(path.substring(0, index) + "/" + payload + "/" + path.substring(index + 1));
            index = path.indexOf('/', index + 1);
        }
        list.add(path + "/" + payload);
        list.add(path + "/" + payload + "/");
        return list;
    }

    @Override public String getTabCaption() { return extensionName; }
    @Override public Component getUiComponent() { return mainPanel; }

    class ScanTask {
        int task_id; String method; String url; int orig_len;
        List<PayloadResult> results = new CopyOnWriteArrayList<>();
        ScanTask(int id, String m, String u, int len) { this.task_id = id; this.method = m; this.url = u; this.orig_len = len; }
    }

    class PayloadResult {
        String type, payload; int newLen, diff, timeMs, status; IHttpRequestResponse reqRes;
        PayloadResult(String t, String p, int nl, int d, int tm, int s, IHttpRequestResponse rr) {
            type = t; payload = p; newLen = nl; diff = d; timeMs = tm; status = s; reqRes = rr;
        }
    }

    class AddTaskRunnable implements Runnable {
        BurpExtender ext; ScanTask task;
        AddTaskRunnable(BurpExtender ext, ScanTask task) { this.ext = ext; this.task = task; }
        public void run() { ext.scanTasks.add(task); ext.urlTableModel.addRow(new Object[]{task.task_id, task.method, task.url, task.orig_len}); }
    }

    class AddPayloadRunnable implements Runnable {
        BurpExtender ext; ScanTask task; PayloadResult pr;
        AddPayloadRunnable(BurpExtender ext, ScanTask task, PayloadResult pr) { this.ext = ext; this.task = task; this.pr = pr; }
        public void run() {
            task.results.add(pr);
            int row = ext.urlTable.getSelectedRow();
            if (row != -1 && ext.scanTasks.get(ext.urlTable.convertRowIndexToModel(row)).task_id == task.task_id) {
                ext.payloadTableModel.addRow(new Object[]{pr.type, pr.payload, pr.newLen, pr.diff, pr.timeMs, pr.status});
            }
        }
    }
}