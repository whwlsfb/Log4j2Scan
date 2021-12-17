package burp.utils;

public class Config {
    public enum FuzzMode {
        EachFuzz, Crazy
    }

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
    public static final String ENABLED_FUZZ_HEADER = "enabled_fuzz_header";
    public static final String ENABLED_FUZZ_URL = "enabled_fuzz_url";
    public static final String ENABLED_FUZZ_BODY = "enabled_fuzz_body";
    public static final String ENABLED_FUZZ_COOKIE = "enabled_fuzz_cookie";
    public static final String ENABLED_FUZZ_BODY_FORM = "enabled_fuzz_body_form";
    public static final String ENABLED_FUZZ_BODY_JSON = "enabled_fuzz_body_json";
    public static final String ENABLED_FUZZ_BODY_XML = "enabled_fuzz_body_xml";
    public static final String ENABLED_FUZZ_BODY_MULTIPART = "enabled_fuzz_body_multipart";
    public static final String ENABLED_FUZZ_BAD_JSON = "enabled_fuzz_bad_json";
    public static final String FUZZ_MODE = "fuzz_mode";

    public static String get(String name) {
        return Utils.Callback.loadExtensionSetting(name);
    }

    public static String get(String name, String defaultValue) {
        String val = Utils.Callback.loadExtensionSetting(name);
        return val == null || val.isEmpty() ? defaultValue : val;
    }

    public static boolean getBoolean(String name, boolean defaultValue) {
        String val = Utils.Callback.loadExtensionSetting(name);
        return val == null || val.isEmpty() ? defaultValue : val.equals("1");
    }

    public static void set(String name, String value) {
        Utils.Callback.saveExtensionSetting(name, value);
    }

    public static void setBoolean(String name, boolean value) {
        Utils.Callback.saveExtensionSetting(name, value ? "1" : "0");
    }
}
