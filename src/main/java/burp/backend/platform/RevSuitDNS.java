package burp.backend.platform;

import burp.backend.IBackend;
import burp.poc.IPOC;
import burp.utils.HttpUtils;
import burp.utils.Utils;
import com.alibaba.fastjson.JSONObject;
import okhttp3.*;
import org.jetbrains.annotations.Nullable;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

public class RevSuitDNS implements IBackend {
    OkHttpClient client = new OkHttpClient().newBuilder().cookieJar(new CookieJar() {
        @Override
        public void saveFromResponse(HttpUrl url, List<Cookie> cookies) {
            return;
        }

        @Override
        public List<Cookie> loadForRequest(HttpUrl url) {
            List<Cookie> cookies = new ArrayList<>();
            cookies.add(new Cookie.Builder().domain(url.host()).name("token").value(token).build());
            return cookies;
        }
    }).connectTimeout(50, TimeUnit.SECONDS).
            callTimeout(50, TimeUnit.SECONDS).
            readTimeout(3, TimeUnit.MINUTES).build();
    String serverAddr;
    String rootDomain;
    String token;
    String dnsFlag = "";

    public RevSuitDNS(String rsServerAddr, String rootDomain, String token) {
        this.token = token;
        this.serverAddr = rsServerAddr.endsWith("/") ? rsServerAddr : rsServerAddr + "/";
        this.rootDomain = rootDomain;
        initRMIEnv();
    }

    private void initRMIEnv() {
        try {
            JSONObject createDNSRuleReq = new JSONObject();
            String flag = Utils.GetRandomString(Utils.GetRandomNumber(5, 10)).toLowerCase();
            createDNSRuleReq.put("flag_format", flag);
            createDNSRuleReq.put("name", String.format("%s Create by Log4j2Scan", flag));
            createDNSRuleReq.put("value", "127.0.0.1");
            JSONObject rmiConfig = JSONObject.parseObject(request("revsuit/api/rule/dns", "POST", createDNSRuleReq.toString()));
            if (rmiConfig.get("status").equals("succeed")) {
                Utils.Callback.printOutput(String.format("create revsuit dns rule '%s' succeed!\r\n", flag));
                dnsFlag = flag;
            } else {
                Utils.Callback.printOutput(String.format("create revsuit dns rule '%s' failed! msg: %s\r\n", flag, rmiConfig.get("status")));
            }
        } catch (Exception ex) {
            Utils.Callback.printOutput(ex.toString());
        }
    }

    private String request(String url) throws Exception {
        return request(url, "GET", null);
    }

    private String request(String url, String method, @Nullable String postBody) throws Exception {
        Request.Builder reqBuilder = HttpUtils.GetDefaultRequest(serverAddr + url);
        if (postBody != null) {
            reqBuilder.header("Content-Type", "application/json;charset=utf-8");
            reqBuilder.method(method, RequestBody.create(postBody.getBytes(StandardCharsets.UTF_8)));
        }
        return client.newCall(reqBuilder.build()).execute().body().string();
    }

    @Override
    public String getName() {
        return "RevSuit-RMI";
    }

    @Override
    public String getNewPayload() {
        return (Utils.getCurrentTimeMillis() + Utils.GetRandomString(5) + "." + dnsFlag + "." + rootDomain).toLowerCase();
    }

    @Override
    public boolean CheckResult(String payload) {
        try {
            String resp = request(String.format("revsuit/api/record/dns?page=1&pageSize=5&order=desc&domain=%s", URLEncoder.encode(payload, "utf-8")));
            return resp.toLowerCase().contains(payload);
        } catch (Exception ex) {
            Utils.Callback.printOutput(ex.toString());
            return false;
        }
    }

    @Override
    public boolean flushCache() {
        return flushCache(10);
    }

    @Override
    public boolean flushCache(int count) {
        return true;
    }

    @Override
    public boolean getState() {
        return !dnsFlag.equals("");
    }

    @Override
    public int[] getSupportedPOCTypes() {
        return new int[]{IPOC.POC_TYPE_RMI, IPOC.POC_TYPE_LDAP};
    }
}
