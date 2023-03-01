package burp.backend.platform;

import burp.backend.IBackend;
import burp.poc.IPOC;
import burp.utils.Config;
import burp.utils.HttpUtils;
import burp.utils.Utils;
import okhttp3.OkHttpClient;
import okhttp3.Response;

import java.util.concurrent.TimeUnit;


public class Eyes implements IBackend {
    OkHttpClient client = new OkHttpClient().newBuilder().
            connectTimeout(3000, TimeUnit.SECONDS).
            callTimeout(3000, TimeUnit.SECONDS).build();

    String rootDomain;
    String token;
    String cache = "";

    public Eyes() {
        this.rootDomain = Config.get(Config.Eyes_IDENTIFIER);
        this.token = Config.get(Config.Eyes_TOKEN);
    }

    @Override
    public boolean supportBatchCheck() {
        return false;
    }

    @Override
    public String[] batchCheck(String[] payloads) {
        return new String[0];
    }

    @Override
    public String getName() {
        return "https://github.com/lijiejie/eyes.sh";
    }

    @Override
    public String getNewPayload() {
        return Utils.getCurrentTimeMillis() + Utils.GetRandomString(5).toLowerCase() + "." + rootDomain;
    }

    @Override
    public boolean CheckResult(String payload) {
        try {
            String prefixDomain = this.rootDomain.split("\\.")[0];
            String adminDomain = this.rootDomain.replace(prefixDomain+".", "");
            payload = payload.replace("."+this.rootDomain, "");
            Response resp = client.newCall(HttpUtils.GetDefaultRequest("http://" + adminDomain + "/api/dns/" + prefixDomain + "/" + payload  + "/?token=" + this.token).build()).execute();
            assert resp.body() != null;
            if (resp.body().string().equals("True")){
                return true;
            }
        } catch (Exception ex) {
            System.out.println(ex);
            return false;
        }
        return false;
    }

    @Override
    public boolean flushCache(int count) {
        return flushCache();
    }

    @Override
    public boolean flushCache() {
        return true;
    }

    @Override
    public boolean getState() {
        return true;
    }

    @Override
    public void close() {
    }

    @Override
    public int[] getSupportedPOCTypes() {
        return new int[]{IPOC.POC_TYPE_LDAP, IPOC.POC_TYPE_RMI};
    }
}
