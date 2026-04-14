package burp.models;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

public class ScanTask {
    public int task_id;
    public String method;
    public String url;
    public int orig_len;
    public List<PayloadResult> results = new CopyOnWriteArrayList<>();

    public ScanTask(int id, String m, String u, int len) {
        this.task_id = id;
        this.method = m;
        this.url = u;
        this.orig_len = len;
    }
}
