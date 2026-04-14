package burp;

import burp.models.*;
import burp.config.Payloads;
import burp.ui.GuidePanel;
import burp.core.*;
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

    public IBurpExtenderCallbacks callbacks;
    public IExtensionHelpers helpers;
    private final String extensionName = "403Pro";

    public JPanel mainPanel;
    private JTabbedPane tabs;

    // --- UI 组件 ---
    public DefaultTableModel urlTableModel, payloadTableModel, wafTableModel;
    public JTable urlTable, payloadTable, wafTable;
    private IMessageEditor requestViewer, responseViewer;
    private JTable queryTable, headerTable, methodTable, excludeTable, whitelistTable, regexTable, wafFingerprintTable;

    private JCheckBox chkEnableAutoScan, chkEnableWhitelist;
    private JCheckBox chkProxy, chkRepeater, chkIntruder;
    private JCheckBox chkScanQuery, chkScanHeader, chkScanMethod;
    // 新增：高阶协议绕过、CVE、Host伪造、HPP污染 模块开关
    private JCheckBox chkScanContentType, chkScanChunked, chkScanCve, chkScanHost, chkScanHpp;
    private JTable cveTable, hostTable, hppTable;
    public volatile boolean cScanContentType, cScanChunked, cScanCve, cScanHost, cScanHpp;

    public volatile List<String> cCvePayloads = new ArrayList<>();
    public volatile List<String> cHostPayloads = new ArrayList<>();
    public volatile List<String> cHppPayloads = new ArrayList<>();
    private JTextField txtStatusCodes, txtDelay;
    private JCheckBox chkEnableRegex;

    // WAF 专属控制开关
    private JCheckBox chkEnableWafDetect, chkEnableDynamicBlacklist, chkEnableIpBanCheck;

    // --- 高并发数据存储区 ---
    public final List<ScanTask> scanTasks = new CopyOnWriteArrayList<>();
    private final Set<String> dedupCache = ConcurrentHashMap.newKeySet();
    private IHttpRequestResponse currentlyDisplayedItem;
    public final AtomicInteger taskCounter = new AtomicInteger(1);
    private final ExecutorService executor = Executors.newFixedThreadPool(15);
    private File configDir;

    public ScannerEngine scannerEngine;
    public WafDetector wafDetector;

    private volatile boolean cAutoScan, cWhitelistOnly, cProxy, cRepeater, cIntruder;
    public volatile boolean cScanQuery, cScanHeader, cScanMethod;
    public volatile String cStatusCodes = "401, 403, 404";
    public volatile int cRequestDelay = 0;
    public volatile boolean cEnableRegex, cEnableWafDetect, cEnableDynamicBlacklist, cEnableIpBanCheck;
    private volatile Pattern cRegexPattern = null;

    private volatile int currentRenderId = 0;
    private final ExecutorService renderExecutor = Executors.newSingleThreadExecutor();

    public volatile List<String> cQueryPayloads = new ArrayList<>();
    public volatile List<String> cHeaderPayloads = new ArrayList<>();
    public volatile List<String> cMethodPayloads = new ArrayList<>();
    private volatile List<String> cExcludeExts = new ArrayList<>();
    private volatile List<String> cWhitelist = new ArrayList<>();
    private volatile List<String> cRegexKeywords = new ArrayList<>();
    public volatile Map<String, Pattern> cWafPatterns = new LinkedHashMap<>();

    // ==========================================
    // --- 默认字典库 (全量扩充实战版) ---
    // ==========================================

    // 1. 路径 Fuzz (扩充了 %2f, %00, 双斜杠等针对老旧中间件和 Nginx 漏洞的 Payload)

    // 2. 请求头伪造 (扩充了更全的 IP 欺骗与网关 Host 覆盖头)

    // 3. 动词篡改

    // 4. 静态资源放行

    // WAF 库保持之前的全量库不变 (省略展示，保持你现有的 defaultWafFingerprints 不动即可)
    // 往下直接添加以下新的字典集合：
    // 7. WAF 指纹库 (融合 Nuclei 核心规则，剔除业务冲突)
    
    // 8. 历史 CVE 漏洞 (极大扩充了常见的未授权 API 泄露端点)

    // 9. Host 碰撞字典 (Host Spoofing)

    // 10. 参数污染字典 (HPP)

    // --- WAF 智能引擎数据结构 ---
    
    public final Map<String, WafProfile> wafMap = new ConcurrentHashMap<>();

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName(extensionName);

        callbacks.printOutput("####################################################");
        callbacks.printOutput("  403 Bypasser Pro");
        callbacks.printOutput("  Author:  DLtest007");
        callbacks.printOutput("  Github:  https://github.com/DLtest007/403Bypasser-Pro");
        callbacks.printOutput("####################################################\n");

        String userHome = System.getProperty("user.home");
        configDir = new File(userHome, ".403bypasser");
        if (!configDir.exists()) {
            configDir.mkdirs();
        }

        this.wafDetector = new WafDetector(this);
        this.scannerEngine = new ScannerEngine(this, this.wafDetector);

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
                        setForeground(new Color(200, 50, 50)); setFont(getFont().deriveFont(Font.BOLD));
                    } else {
                        setForeground(Color.BLACK); setFont(getFont().deriveFont(Font.PLAIN));
                    }
                } else { super.setValue(value); }
            }
        });

        // 异步渲染防卡顿机制
        payloadTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting() && urlTable.getSelectedRow() != -1 && payloadTable.getSelectedRow() != -1) {
                try {
                    int uRow = urlTable.convertRowIndexToModel(urlTable.getSelectedRow());
                    int pRow = payloadTable.convertRowIndexToModel(payloadTable.getSelectedRow());
                    ScanTask task = scanTasks.get(uRow);
                    if (pRow >= task.results.size()) return;
                    PayloadResult pr = task.results.get(pRow);

                    final int renderId = ++currentRenderId;
                    renderExecutor.submit(() -> {
                        if (renderId != currentRenderId) return;
                        currentlyDisplayedItem = pr.reqRes;
                        byte[] req = pr.reqRes.getRequest();
                        byte[] res = pr.reqRes.getResponse() != null ? pr.reqRes.getResponse() : new byte[0];

                        requestViewer.setMessage(req, true);
                        if (renderId != currentRenderId) return;
                        responseViewer.setMessage(res, false);
                    });
                } catch (Exception ex) {}
            }
        });
        payloadTable.getColumnModel().getColumn(1).setPreferredWidth(200);

        JPanel urlPanel = new JPanel(new BorderLayout(0, 5));
        urlPanel.add(new JLabel(" 已扫描接口 (Scanned Interfaces)"), BorderLayout.NORTH);
        urlPanel.add(new JScrollPane(urlTable), BorderLayout.CENTER);

        JPanel payloadPanel = new JPanel(new BorderLayout(0, 5));
        payloadPanel.add(new JLabel(" 测试结果 (Payload Results)"), BorderLayout.NORTH);
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
        reqPanel.add(new JLabel(" 请求包 (Request)"), BorderLayout.NORTH);
        reqPanel.add(requestViewer.getComponent(), BorderLayout.CENTER);

        JPanel resPanel = new JPanel(new BorderLayout(0, 5));
        resPanel.add(new JLabel(" 响应包 (Response)"), BorderLayout.NORTH);
        resPanel.add(responseViewer.getComponent(), BorderLayout.CENTER);

        viewerSplit.setLeftComponent(reqPanel);
        viewerSplit.setRightComponent(resPanel);
        viewerSplit.setResizeWeight(0.5);

        dataSplit.setTopComponent(topSplit);
        dataSplit.setBottomComponent(viewerSplit);
        dataSplit.setResizeWeight(0.5);

        // --- 控制面板 (Control Panel) 视觉大升级 ---
        JPanel ctrlPanel = new JPanel();
        ctrlPanel.setLayout(new BoxLayout(ctrlPanel, BoxLayout.Y_AXIS));
        ctrlPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JPanel pnlGlobal = new JPanel(new GridLayout(0, 1, 2, 2));
        pnlGlobal.setBorder(BorderFactory.createTitledBorder("1. 全局与白名单 (Global)"));
        chkEnableAutoScan = new JCheckBox("允许被动监听与扫描", false);
        chkEnableAutoScan.setForeground(new Color(200, 0, 0));
        chkEnableWhitelist = new JCheckBox("开启白名单匹配 (推荐)", false);
        pnlGlobal.add(chkEnableAutoScan); pnlGlobal.add(chkEnableWhitelist);
        ctrlPanel.add(pnlGlobal); ctrlPanel.add(Box.createVerticalStrut(8));

        JPanel pnlSource = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        pnlSource.setBorder(BorderFactory.createTitledBorder("2. 抓取模块来源 (Source)"));
        chkProxy = new JCheckBox("Proxy", true);
        chkRepeater = new JCheckBox("Repeater", true);
        chkIntruder = new JCheckBox("Intruder", false);
        pnlSource.add(chkProxy); pnlSource.add(chkRepeater); pnlSource.add(chkIntruder);
        ctrlPanel.add(pnlSource); ctrlPanel.add(Box.createVerticalStrut(8));

        JPanel pnlDict = new JPanel(new GridLayout(0, 1, 2, 2));
        pnlDict.setBorder(BorderFactory.createTitledBorder("3. 扫描模块开启配置 (模块化选配)"));

        chkScanQuery = new JCheckBox("路径字典 Fuzz (Query)", true); pnlDict.add(chkScanQuery);
        chkScanHeader = new JCheckBox("请求头越权伪造 (Header)", true); pnlDict.add(chkScanHeader);
        chkScanMethod = new JCheckBox("动词篡改降级 (Method)", true); pnlDict.add(chkScanMethod);

        // 追加全新的 5 个高阶模块
        chkScanChunked = new JCheckBox("分块传输穿透 (Chunked)", false); pnlDict.add(chkScanChunked);
        chkScanContentType = new JCheckBox("Content-Type 解析欺骗", false); pnlDict.add(chkScanContentType);
        chkScanCve = new JCheckBox("靶向历史 CVE 探测", false);
        chkScanCve.setForeground(new Color(150, 0, 150)); pnlDict.add(chkScanCve);
        chkScanHost = new JCheckBox("Host 碰撞伪造 (Spoofing)", false); pnlDict.add(chkScanHost);
        chkScanHpp = new JCheckBox("URL 参数污染 (HPP)", false); pnlDict.add(chkScanHpp);

        ctrlPanel.add(pnlDict); ctrlPanel.add(Box.createVerticalStrut(8));

        JPanel pnlWaf = new JPanel(new GridLayout(0, 1, 2, 2));
        pnlWaf.setBorder(BorderFactory.createTitledBorder("4. WAF 防御对抗 (Anti-Ban)"));
        chkEnableWafDetect = new JCheckBox("启用 WAF 识别与拦截接管", true);
        chkEnableWafDetect.setForeground(new Color(200, 50, 0));
        chkEnableDynamicBlacklist = new JCheckBox("启用 PoC 动态拉黑 (防墙)", true);
        chkEnableIpBanCheck = new JCheckBox("启用 IP 封禁智能探活验证", true);
        pnlWaf.add(chkEnableWafDetect); pnlWaf.add(chkEnableDynamicBlacklist); pnlWaf.add(chkEnableIpBanCheck);
        ctrlPanel.add(pnlWaf); ctrlPanel.add(Box.createVerticalStrut(8));

        JPanel pnlTrigger = new JPanel(new GridLayout(0, 1, 2, 2));
        pnlTrigger.setBorder(BorderFactory.createTitledBorder("5. 扫描触发条件 (Trigger)"));
        JPanel pnlStatus = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        pnlStatus.add(new JLabel("目标状态码: "));
        txtStatusCodes = new JTextField("401, 403, 404", 10);
        pnlStatus.add(txtStatusCodes);
        pnlTrigger.add(pnlStatus);

        // 【UI 优化点】重命名假 200 触发开关
        chkEnableRegex = new JCheckBox("开启响应体业务拦截检测 (解决假200 OK)", true);
        pnlTrigger.add(chkEnableRegex);
        ctrlPanel.add(pnlTrigger); ctrlPanel.add(Box.createVerticalStrut(8));

        JPanel pnlRate = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        pnlRate.setBorder(BorderFactory.createTitledBorder("6. 并发控制 (Rate Limit)"));
        pnlRate.add(new JLabel("发包延迟 (ms): "));
        txtDelay = new JTextField("0", 6);
        pnlRate.add(txtDelay);
        ctrlPanel.add(pnlRate); ctrlPanel.add(Box.createVerticalStrut(8));

        JPanel pnlData = new JPanel(new GridLayout(0, 1, 5, 5));
        pnlData.setBorder(BorderFactory.createTitledBorder("7. 缓存管理 (Data)"));
        JButton btnClearCache = new JButton("清空去重缓存 (可重扫)");
        btnClearCache.addActionListener(e -> { dedupCache.clear(); callbacks.printOutput("[*] 去重缓存已清空！"); });
        JButton btnClearData = new JButton("清空所有缓存与WAF记录");
        btnClearData.addActionListener(e -> {
            scanTasks.clear(); urlTableModel.setRowCount(0); payloadTableModel.setRowCount(0);
            dedupCache.clear(); wafMap.clear(); wafTableModel.setRowCount(0); taskCounter.set(1);
            requestViewer.setMessage(new byte[0], true); responseViewer.setMessage(new byte[0], false);
            callbacks.printOutput("[*] 所有缓存已完全重置！");
        });
        pnlData.add(btnClearCache); pnlData.add(btnClearData);
        ctrlPanel.add(pnlData);

        rootSplit.setLeftComponent(dataSplit);
        rootSplit.setRightComponent(ctrlPanel);
        rootSplit.setResizeWeight(0.85);
        dashboardPanel.add(rootSplit, BorderLayout.CENTER);

        // ====== 2. WAF 情报中心 Tab (增强版：支持双击查看拦截详情) ======
        JPanel wafPanel = new JPanel(new BorderLayout(5, 5));
        wafPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // 【UI 优化】：修改表头名称，明确告诉用户可以双击
        wafTableModel = new DefaultTableModel(new String[]{"目标站点 (Host)", "识别的 WAF 指纹", "IP 被墙状态", "被拉黑 PoC 数量 (双击查看)"}, 0) {
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

        // 【核心交互】：添加鼠标双击事件，呼出被拦截的详情面板
        wafTable.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent e) {
                if (e.getClickCount() == 2) { // 监听到双击
                    int row = wafTable.getSelectedRow();
                    if (row != -1) {
                        int modelRow = wafTable.convertRowIndexToModel(row);
                        String host = (String) wafTableModel.getValueAt(modelRow, 0);
                        WafProfile profile = wafMap.get(host);
                        if (profile != null) {
                            wafDetector.showBlacklistedPoCsDialog(host, profile.blacklistedPoCs);
                        }
                    }
                }
            }
        });

        JLabel lblWafCenter = new JLabel(" WAF 动态识别与拦截记录库");
        lblWafCenter.setFont(lblWafCenter.getFont().deriveFont(Font.BOLD));
        wafPanel.add(lblWafCenter, BorderLayout.NORTH);
        wafPanel.add(new JScrollPane(wafTable), BorderLayout.CENTER);

        // ====== 3. 配置中心 (Configuration Panel) 采用 JList+CardLayout 完美还原高级 UI ======
        JPanel configPanel = new JPanel(new BorderLayout());

        // --- 1. 左侧菜单栏 ---
        DefaultListModel<String> menuModel = new DefaultListModel<>();
        String[] menuItems = {
                "📂 路径与参数 (Query)", "🕵️ 请求头伪造 (Header)", "🔄 动词篡改 (Method)",
                "⏭️ 静态资源放行 (Exclude)", "✅ 域名白名单 (Whitelist)", "🎭 假200特征 (Regex)",
                "🛡️ WAF指纹库 (WAF)", "🎯 靶向 CVE 漏洞 (CVE)", "🌐 Host 碰撞伪造 (Host)", "🔗 URL 参数污染 (HPP)"
        };
        for (String item : menuItems) { menuModel.addElement(item); }

        JList<String> menuList = new JList<>(menuModel);
        menuList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        menuList.setFont(menuList.getFont().deriveFont(Font.BOLD, 13f));
        menuList.setFixedCellHeight(38); // 增加行高，看着非常舒展
        menuList.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

        // 给左侧列表加一个灰蓝色背景色，并加右边框线（高度还原 SQLSniper 质感）
        menuList.setBackground(new Color(242, 246, 252));
        JScrollPane menuScroll = new JScrollPane(menuList);
        menuScroll.setPreferredSize(new Dimension(220, 0));
        menuScroll.setBorder(BorderFactory.createMatteBorder(0, 0, 0, 1, Color.LIGHT_GRAY));
        configPanel.add(menuScroll, BorderLayout.WEST);

        // --- 2. 右侧配置内容区 (CardLayout) ---
        CardLayout cardLayout = new CardLayout();
        JPanel contentCards = new JPanel(cardLayout);

        queryTable = buildConfigModule(contentCards, menuItems[0], "bypasser_query.txt", Payloads.defaultQueryPayloads);
        headerTable = buildConfigModule(contentCards, menuItems[1], "bypasser_header.txt", Payloads.defaultHeaderPayloads);
        methodTable = buildConfigModule(contentCards, menuItems[2], "bypasser_method.txt", Payloads.defaultMethodPayloads);
        excludeTable = buildConfigModule(contentCards, menuItems[3], "bypasser_ext.txt", Payloads.defaultExcludeExts);
        whitelistTable = buildConfigModule(contentCards, menuItems[4], "bypasser_whitelist.txt", Payloads.defaultWhitelist);
        regexTable = buildConfigModule(contentCards, menuItems[5], "bypasser_regex.txt", Payloads.defaultRegexKeywords);
        wafFingerprintTable = buildConfigModule(contentCards, menuItems[6], "bypasser_waf.txt", Payloads.defaultWafFingerprints);
        cveTable = buildConfigModule(contentCards, menuItems[7], "bypasser_cve.txt", Payloads.defaultCvePayloads);
        hostTable = buildConfigModule(contentCards, menuItems[8], "bypasser_host.txt", Payloads.defaultHostPayloads);
        hppTable = buildConfigModule(contentCards, menuItems[9], "bypasser_hpp.txt", Payloads.defaultHppPayloads);

        configPanel.add(contentCards, BorderLayout.CENTER);

        // --- 3. 绑定点击切换事件 ---
        menuList.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                String selected = menuList.getSelectedValue();
                if (selected != null) {
                    cardLayout.show(contentCards, selected);
                }
            }
        });
        menuList.setSelectedIndex(0); // 默认选中第一项

        // ====== 4. 独立的保姆级编写指南 Tab ======
        JPanel helpPanel = new GuidePanel();

        // 将各大面板加入主 Tab
        tabs.addTab("扫描大盘 (Dashboard)", dashboardPanel);
        tabs.addTab("WAF 拦截情报中心", wafPanel);
        tabs.addTab("配置中心 (Configuration)", configPanel);
        tabs.addTab("📖 编写指南 (Help)", helpPanel); // <--- 将指南作为第4个大标签页独立出来

        JPanel bottomInfoPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel infoLabel = new JLabel(" 配置文件保存在: " + configDir.getAbsolutePath() + " | (多线程内存隔离同步已开启)");
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

        // 基础模块监听
        chkScanQuery.addActionListener(syncAction);
        chkScanHeader.addActionListener(syncAction);
        chkScanMethod.addActionListener(syncAction);

        // 👇 【核心修复：补全这 5 个新增高阶模块的实时监听】
        chkScanChunked.addActionListener(syncAction);
        chkScanContentType.addActionListener(syncAction);
        chkScanCve.addActionListener(syncAction);
        chkScanHost.addActionListener(syncAction);
        chkScanHpp.addActionListener(syncAction);

        // WAF与杂项监听
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
        txtDelay.getDocument().addDocumentListener(docSync);
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
            cScanChunked = chkScanChunked.isSelected();
            cScanContentType = chkScanContentType.isSelected();
            cScanCve = chkScanCve.isSelected();
            cScanHost = chkScanHost.isSelected();
            cScanHpp = chkScanHpp.isSelected();
            try {
                cRequestDelay = Integer.parseInt(txtDelay.getText().trim());
            } catch (Exception e) {
                cRequestDelay = 0;
            }
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
            if (cveTable.isEditing()) cveTable.getCellEditor().stopCellEditing();
            if (hostTable.isEditing()) hostTable.getCellEditor().stopCellEditing();
            if (hppTable.isEditing()) hppTable.getCellEditor().stopCellEditing();
            cCvePayloads = getTableData(cveTable);
            cHostPayloads = getTableData(hostTable);
            cHppPayloads = getTableData(hppTable);

            if (cEnableRegex && !cRegexKeywords.isEmpty()) {
                StringJoiner sj = new StringJoiner("|");
                for (String kw : cRegexKeywords) {
                    if (!kw.trim().isEmpty()) sj.add(Pattern.quote(kw.trim()));
                }
                cRegexPattern = sj.length() > 0 ? Pattern.compile("(?i)(" + sj.toString() + ")") : null;
            } else {
                cRegexPattern = null;
            }

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

    // 【修改一】将参数 JTabbedPane 改为了 JPanel，适配高级卡片布局
    private JTable buildConfigModule(JPanel parent, String title, String filename, List<String> defaultData) {
        JPanel panel = new JPanel(new BorderLayout(8, 8));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 15, 10, 15));

        JLabel lblTitle = new JLabel("设置面板: " + title);
        lblTitle.setFont(lblTitle.getFont().deriveFont(Font.BOLD, 15f));
        panel.add(lblTitle, BorderLayout.NORTH);

        File file = new File(configDir, filename);
        List<String> data = defaultData;
        if (!file.exists()) {
            try { Files.write(file.toPath(), defaultData); } catch (IOException ignored) {}
        } else {
            try { data = Files.readAllLines(file.toPath()); } catch (IOException ignored) {}
        }

        DefaultTableModel model = new DefaultTableModel(new String[]{"规则配置内容 (双击单元格即可修改)"}, 0);
        for (String item : data) {
            if (!item.trim().isEmpty()) model.addRow(new Object[]{item.trim()});
        }
        JTable table = new JTable(model);
        table.setRowHeight(24);

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
        txt.addActionListener(e -> btnAdd.doClick());

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

        // 【核心修改】以 CardLayout 的方式添加到父面板
        parent.add(panel, title);
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
            updateCachesFromUI();
        }
    }

    private List<String> getTableData(JTable table) {
        List<String> list = new ArrayList<>();
        for (int i = 0; i < table.getRowCount(); i++) {
            list.add(table.getValueAt(i, 0).toString());
        }
        return list;
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
        if (!cWhitelistOnly) return true;
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

    public int getBodyLength(byte[] response) {
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

        if (wafMap.containsKey(url.getHost()) && wafMap.get(url.getHost()).isIpBanned) {
            return;
        }

        IResponseInfo info = helpers.analyzeResponse(response);

        String mime = info.getStatedMimeType();
        if (mime != null && (mime.equalsIgnoreCase("script") || mime.equalsIgnoreCase("CSS") || mime.toLowerCase().contains("image") || mime.toLowerCase().contains("video"))) {
            return;
        }

        int statusCode = info.getStatusCode();
        boolean matched = false;

        String[] targetCodes = cStatusCodes.split(",");
        for (String code : targetCodes) {
            if (String.valueOf(statusCode).equals(code.trim())) { matched = true; break; }
        }

        if (!matched && cEnableRegex && cRegexPattern != null) {
            byte[] body = Arrays.copyOfRange(response, info.getBodyOffset(), response.length);
            if (body.length > 0 && body.length < 10240) {
                String utf8Body = new String(body, java.nio.charset.StandardCharsets.UTF_8);
                if (cRegexPattern.matcher(utf8Body).find()) {
                    matched = true;
                }
            }
        }

        if (matched) {
            String dedupKey = reqInfo.getMethod() + "_" + url.getHost() + url.getPath();
            if (isExcluded(url) || dedupCache.contains(dedupKey)) return;
            dedupCache.add(dedupKey);

            List<String> modes = new ArrayList<>();
            if (cScanQuery) modes.add("query");
            if (cScanHeader) modes.add("header");
            if (cScanMethod) modes.add("method");
            if (cScanChunked) modes.add("chunked");
            if (cScanContentType) modes.add("content_type");
            if (cScanCve) modes.add("cve");
            if (cScanHost) modes.add("host");
            if (cScanHpp) modes.add("hpp");

            if (!modes.isEmpty()) {
                callbacks.printOutput("[+] 触发被动扫描: " + url.toString());
                executor.submit(() -> scannerEngine.doScan(messageInfo, modes));
            }
        }
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> list = new ArrayList<>();
        JMenu menu = new JMenu("403 Bypass (主动扫描)");

        JMenuItem itemQuery = new JMenuItem("仅扫描路径字典 (Query)");
        itemQuery.addActionListener(e -> triggerManualScan(invocation, Arrays.asList("query")));

        JMenuItem itemHeader = new JMenuItem("仅扫描请求头字典 (Header)");
        itemHeader.addActionListener(e -> triggerManualScan(invocation, Arrays.asList("header")));

        JMenuItem itemAll = new JMenuItem("全部扫描 (All)");
        itemAll.addActionListener(e -> triggerManualScan(invocation, Arrays.asList("query", "header", "method", "chunked", "content_type", "cve", "host", "hpp")));

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
            callbacks.printOutput("[+] 手动触发强制扫描: " + req.getUrl().toString());
            executor.submit(() -> scannerEngine.doScan(msg, modes));
        }
    }

    @Override public String getTabCaption() { return extensionName; }
    @Override public Component getUiComponent() { return mainPanel; }

    public static class AddTaskRunnable implements Runnable {
        BurpExtender ext; ScanTask task;
        public AddTaskRunnable(BurpExtender ext, ScanTask task) { this.ext = ext; this.task = task; }
        public void run() { ext.scanTasks.add(task); ext.urlTableModel.addRow(new Object[]{task.task_id, task.method, task.url, task.orig_len}); }
    }

    public static class AddPayloadRunnable implements Runnable {
        BurpExtender ext; ScanTask task; PayloadResult pr;
        public AddPayloadRunnable(BurpExtender ext, ScanTask task, PayloadResult pr) { this.ext = ext; this.task = task; this.pr = pr; }
        public void run() {
            task.results.add(pr);
            int row = ext.urlTable.getSelectedRow();
            if (row != -1 && ext.scanTasks.get(ext.urlTable.convertRowIndexToModel(row)) == task) {
                ext.payloadTableModel.addRow(new Object[]{pr.type, pr.payload, pr.newLen, pr.diff, pr.timeMs, pr.status});
            }
        }
    }
}