package burp.models;

import burp.IHttpRequestResponse;

public class PayloadResult {
    public String type, payload;
    public int newLen, diff, timeMs, status;
    public IHttpRequestResponse reqRes;

    public PayloadResult(String t, String p, int nl, int d, int tm, int s, IHttpRequestResponse rr) {
        type = t;
        payload = p;
        newLen = nl;
        diff = d;
        timeMs = tm;
        status = s;
        reqRes = rr;
    }
}
