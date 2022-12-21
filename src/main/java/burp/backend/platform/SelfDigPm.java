package burp.backend.platform;

import burp.backend.IBackend;
import burp.poc.IPOC;
import burp.utils.Config;
import burp.utils.HttpUtils;
import burp.utils.Utils;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.sun.net.httpserver.BasicAuthenticator;
import okhttp3.FormBody;
import okhttp3.OkHttpClient;
import okhttp3.Response;

import java.math.BigInteger;
import java.net.http.HttpRequest;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.TimeUnit;

import static burp.utils.HttpUtils.GetDefaultRequest;


public class SelfDigPm implements IBackend {
    OkHttpClient client = new OkHttpClient().newBuilder().
            connectTimeout(3000, TimeUnit.SECONDS).
            callTimeout(3000, TimeUnit.SECONDS).build();
    String platformUrl;
    String rootDomain = "";
    String userDomain = "";
    String token;
    String token2;
    String cache = "";

    public SelfDigPm() {
        this.platformUrl = Config.get(Config.SelfDigPm_ADMIN_URL);
        this.token = Config.get(Config.SelfDigPm_TOKEN);
        this.initDomain1();
    }

    private void initDomain1() {
        try {
            Utils.Callback.printOutput("000");
            Utils.Callback.printOutput("get domain1...");
            Utils.Callback.printOutput(String.format("platformUrl1: %s",platformUrl));
            Utils.Callback.printOutput(String.format("Basic token1: %s",token));
            Response resp = client.newCall(GetDefaultRequest(platformUrl + "get_domain?t=0." + Math.abs(Utils.getRandomLong())).addHeader("Authorization","Basic " + this.token).build()).execute();

            String[] rootDomains = JSONObject.parseObject(resp.body().string(), String[].class);
            rootDomain = rootDomains[0];
            resp = client.newCall(GetDefaultRequest(platformUrl + "new_gen").post(new FormBody.Builder().add("domain", rootDomains[0]).build()).addHeader("Authorization","Basic " + this.token).build()).execute();
            JSONObject jobj = JSONObject.parseObject(resp.body().string());
            userDomain = (String) jobj.get("domain");
            token2 = (String) jobj.get("token");
            Utils.Callback.printOutput(String.format("Identifier token2: %s",token2));
            userDomain = userDomain.endsWith(".") ? userDomain.substring(0, userDomain.length() - 1) : userDomain;
            Utils.Callback.printOutput(String.format("userDomain: %s", userDomain));
            Utils.Callback.printOutput(String.format("rootDomain: %s", rootDomain));
            //Utils.Callback.printOutput(String.format("ShareLink: https://%s/?domain=%s&token=%s&key=%s.",platformUrl, rootDomain, token, userDomain));
            Utils.Callback.printOutput("001");
        } catch (Exception ex) {
            Utils.Callback.printError("initDomain1 failed: " + ex.getMessage());
        }
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
        return "https://github.com/yumusb/DNSLog-Platform-Golang";
    }

    @Override
    public String getNewPayload() {
        return Utils.getCurrentTimeMillis() + Utils.GetRandomString(5).toLowerCase() + "." + userDomain;
    }

    @Override
    public boolean CheckResult(String domain) {
        try {
            return cache.contains(domain);
        } catch (Exception ex) {
            System.out.println(ex);
            return false;
        }
    }

    @Override
    public boolean flushCache(int count) {
        return flushCache();
    }

    @Override
    public boolean flushCache() {
        try {
            Response resp = client.newCall(HttpUtils.GetDefaultRequest(platformUrl + "get_results").
                    post(new FormBody.Builder().
                            add("domain", rootDomain).
                            add("token", token2)
                            .build()).addHeader("Authorization","Basic " + this.token).build()).execute();
            cache = resp.body().string().toLowerCase();
            return true;
        } catch (Exception ex) {
            System.out.println(ex);
            return false;
        }
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
