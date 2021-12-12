package burp.backend.platform;

import burp.backend.IBackend;
import burp.poc.IPOC;
import burp.utils.HttpUtils;
import burp.utils.Utils;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import okhttp3.OkHttpClient;
import okhttp3.Response;

import java.util.concurrent.TimeUnit;


public class Ceye implements IBackend {
    OkHttpClient client = new OkHttpClient().newBuilder().
            connectTimeout(3000, TimeUnit.SECONDS).
            callTimeout(3000, TimeUnit.SECONDS).build();
    String platformUrl = "http://api.ceye.io/";
    String rootDomain = "<rootDomain>";
    String token = "<token>";

    @Override
    public String getName() {
        return "Ceye.io";
    }

    @Override
    public String getNewPayload() {
        return Utils.getCurrentTimeMillis() + Utils.GetRandomString(5) + "." + rootDomain;
    }

    @Override
    public boolean CheckResult(String domain) {
        try {
            Response resp = client.newCall(HttpUtils.GetDefaultRequest(platformUrl + "v1/records?token=" + token + "&type=dns&filter=" + domain.toLowerCase().substring(0, domain.indexOf("."))).build()).execute();
            JSONObject jObj = JSONObject.parseObject(resp.body().string().toLowerCase());
            if (jObj.containsKey("data")) {
                return (((JSONArray) jObj.get("data")).size() > 0);
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
    public int[] getSupportedPOCTypes() {
        return new int[]{IPOC.POC_TYPE_LDAP, IPOC.POC_TYPE_RMI};
    }
}
