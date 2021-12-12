package burp.backend.platform;

import burp.backend.IBackend;
import burp.poc.IPOC;
import burp.utils.HttpUtils;
import burp.utils.Utils;
import com.alibaba.fastjson.JSONObject;
import okhttp3.*;
import org.jetbrains.annotations.Nullable;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

public class RevSuitRMI implements IBackend {
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
    String rootRMIUrl;
    String token;
    String rmiFlag = "";

    public RevSuitRMI(String rsServerAddr, String vpsRMIAddr, String token) {
        this.token = token;
        this.serverAddr = rsServerAddr.endsWith("/") ? rsServerAddr : rsServerAddr + "/";
        this.rootRMIUrl = vpsRMIAddr.endsWith("/") ? vpsRMIAddr : vpsRMIAddr + "/";
        initRMIEnv();
    }

    private void initRMIEnv() {
        try {
            JSONObject createRMIRuleReq = new JSONObject();
            String flag = Utils.GetRandomString(Utils.GetRandomNumber(5, 10)).toLowerCase();
            createRMIRuleReq.put("flag_format", flag);
            createRMIRuleReq.put("name", String.format("%s Create by Log4j2Scan", flag));
            JSONObject rmiConfig = JSONObject.parseObject(request("revsuit/api/rule/rmi", "POST", createRMIRuleReq.toString()));
            if (rmiConfig.get("status").equals("succeed")) {
                Utils.Callback.printOutput(String.format("create revsuit rmi rule '%s' succeed!\r\n", flag));
                rmiFlag = flag;
            } else {
                Utils.Callback.printOutput(String.format("create revsuit rmi rule '%s' failed! msg: %s\r\n", flag, rmiConfig.get("status")));
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
        return rootRMIUrl + rmiFlag + "/" + Utils.GetRandomString(10);
    }

    @Override
    public boolean CheckResult(String payload) {
        try {
            String purePayload = payload.substring(payload.indexOf(rmiFlag));
            String resp = request(String.format("revsuit/api/record/rmi?page=1&pageSize=5&order=desc&path=%s", URLEncoder.encode(purePayload, "utf-8")));
            return resp.contains(purePayload);
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
        return !rmiFlag.equals("");
    }

    @Override
    public int[] getSupportedPOCTypes() {
        return new int[]{IPOC.POC_TYPE_RMI};
    }
}
