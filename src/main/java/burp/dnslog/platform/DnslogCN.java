package burp.dnslog.platform;

import burp.dnslog.IDnslog;
import burp.utils.HttpUtils;
import burp.utils.Utils;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import okhttp3.*;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.TimeUnit;

import static burp.utils.HttpUtils.GetDefaultRequest;

public class DnslogCN implements IDnslog {
    OkHttpClient client = new OkHttpClient().newBuilder().cookieJar(new CookieJar() {
        private final HashMap<String, List<Cookie>> cookieStore = new HashMap<>();

        @Override
        public void saveFromResponse(HttpUrl url, List<Cookie> cookies) {
            cookieStore.put(url.host(), cookies);
        }

        @Override
        public List<Cookie> loadForRequest(HttpUrl url) {
            List<Cookie> cookies = cookieStore.get(url.host());
            return cookies != null ? cookies : new ArrayList<Cookie>();
        }
    }).connectTimeout(50, TimeUnit.SECONDS).
            callTimeout(50, TimeUnit.SECONDS).
            readTimeout(3, TimeUnit.MINUTES).build();
    String platformUrl = "http://www.dnslog.cn/";
    String rootDomain = "";
    String dnsLogResultCache = "";

    Instant lastRequestTime = null;

    public DnslogCN() {
        this.initDomain();
    }

    private void initDomain() {
        try {
            Utils.Callback.printOutput("get domain...");
            Response resp = client.newCall(GetDefaultRequest(platformUrl + "/getdomain.php").build()).execute();
            rootDomain = resp.body().string();
            Utils.Callback.printOutput(String.format("Domain: %s", rootDomain));
            startSessionHeartbeat();
        } catch (Exception ex) {
            Utils.Callback.printError("initDomain failed: " + ex.getMessage());
        }
    }

    private void startSessionHeartbeat() {
        Timer timer = new Timer();
        timer.schedule(new TimerTask() {
            @Override
            public void run() {
                flushCache();
            }
        }, 0, 30 * 1000); //30s
    }

    @Override
    public String getName() {
        return "Dnslog.cn";
    }

    @Override
    public String getNewDomain() {
        return Utils.getCurrentTimeMillis() + Utils.GetRandomString(5) + "." + rootDomain;
    }

    public boolean flushCache() {
        try {
            Response resp = client.newCall(HttpUtils.GetDefaultRequest(platformUrl + "getrecords.php").build()).execute();
            dnsLogResultCache = resp.body().string();
            lastRequestTime = Instant.now();
            return true;
        } catch (Exception ex) {
            return false;
        }
    }

    @Override
    public boolean CheckResult(String domain) {
        return dnsLogResultCache.contains(domain);
    }

    @Override
    public boolean getState() {
        return rootDomain != "";
    }
}
