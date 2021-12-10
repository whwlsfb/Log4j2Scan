package burp.dnslog.platform;

import burp.dnslog.IDnslog;
import burp.utils.HttpUtils;
import burp.utils.Utils;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import okhttp3.*;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
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
    }).connectTimeout(30, TimeUnit.SECONDS).
            callTimeout(30, TimeUnit.SECONDS).build();
    String platformUrl = "http://www.dnslog.cn/";
    String rootDomain = "";

    public DnslogCN() {
        this.initDomain();
    }

    private void initDomain() {
        try {
            Response resp = client.newCall(GetDefaultRequest(platformUrl + "/getdomain.php").build()).execute();
            rootDomain = resp.body().string();
        } catch (Exception ex) {
            System.out.println(ex);
        }
    }

    @Override
    public String getName() {
        return "Dnslog.cn";
    }

    @Override
    public String getNewDomain() {
        return Utils.getCurrentTimeMillis() + Utils.GetRandomString(5) + "." + rootDomain;
    }

    @Override
    public boolean CheckResult(String domain) {
        try {
            Response resp = client.newCall(HttpUtils.GetDefaultRequest(platformUrl + "getrecords.php").build()).execute();
            String respStr = resp.body().string();
            return respStr.contains(domain);
        } catch (Exception ex) {
            System.out.println(ex);
            return false;
        }
    }

    @Override
    public boolean getState() {
        try {
            Response resp = client.newCall(HttpUtils.GetDefaultRequest(platformUrl).build()).execute();
            return resp.code() == 200;
        } catch (Exception ex) {
            return false;
        }
    }
}
