package burp.utils;

public class Config {
    public static final String CURRENT_BACKEND = "current_backend";
    public static final String CEYE_IDENTIFIER = "ceye_identifier";
    public static final String CEYE_TOKEN = "ceye_token";
    public static final String REVSUIT_RMI_ADMIN_URL = "revsuit_rmi_admin_url";
    public static final String REVSUIT_RMI_ADDR = "revsuit_rmi_addr";
    public static final String REVSUIT_RMI_TOKEN = "revsuit_rmi_token";
    public static final String REVSUIT_DNS_ADMIN_URL = "revsuit_dns_admin_url";
    public static final String REVSUIT_DNS_DOMAIN = "revsuit_dns_domain";
    public static final String REVSUIT_DNS_TOKEN = "revsuit_dns_token";
    public static final String ENABLED_POC_IDS = "enabled_poc_ids";
    public static final String GODNSLOG_IDENTIFIER = "godnslog_identifier";
    public static final String GODNSLOG_TOKEN = "godnslog_token";

    public static String get(String name) {
        return Utils.Callback.loadExtensionSetting(name);
    }

    public static String get(String name, String defaultValue) {
        String val = Utils.Callback.loadExtensionSetting(name);
        return val == null || val.isEmpty() ? defaultValue : val;
    }

    public static void set(String name, String value) {
        Utils.Callback.saveExtensionSetting(name, value);
    }
}
