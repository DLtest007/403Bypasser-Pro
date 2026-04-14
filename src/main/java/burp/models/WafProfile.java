package burp.models;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class WafProfile {
    public String wafName;
    public boolean isIpBanned = false;
    public Set<String> blacklistedPoCs = ConcurrentHashMap.newKeySet();
}
