package burp.backend.platform;

import burp.backend.IBackend;
import burp.poc.IPOC;
import burp.utils.Config;
import burp.utils.HttpUtils;
import burp.utils.Utils;
import com.alibaba.fastjson.JSONArray;
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
    boolean serverSideSupportBatchCheck = false;

    @Override
    public boolean supportBatchCheck() {
        return serverSideSupportBatchCheck;
    }

    public RevSuitRMI() {
        this.token = Config.get(Config.REVSUIT_RMI_TOKEN);
        String serverAddr = Config.get(Config.REVSUIT_RMI_ADMIN_URL);
        this.serverAddr = serverAddr.endsWith("/") ? serverAddr : serverAddr + "/";
        String rootRMIUrl = Config.get(Config.REVSUIT_RMI_ADDR);
        this.rootRMIUrl = rootRMIUrl.endsWith("/") ? rootRMIUrl : rootRMIUrl + "/";
        initRMIEnv();
        checkServiceSideBatchCheckSupport();
    }

    private void initRMIEnv() {
        try {
            JSONObject createRMIRuleReq = new JSONObject();
            String flag = Utils.GetRandomString(Utils.GetRandomNumber(5, 10)).toLowerCase();
            createRMIRuleReq.put("flag_format", flag);
            createRMIRuleReq.put("name", String.format("%s Create by Log4j2Scan", flag));
            JSONObject rmiConfig = JSONObject.parseObject(request("revsuit/api/rule/rmi", "POST", createRMIRuleReq.toString()));
            if (rmiConfig.get("status").equals("succeed")) {
                Utils.Callback.printOutput(String.format("Create RevSuit rmi rule '%s' succeed!\r\n", flag));
                rmiFlag = flag;
            } else {
                Utils.Callback.printOutput(String.format("Create RevSuit rmi rule '%s' failed! msg: %s\r\n", flag, rmiConfig.get("status")));
            }
        } catch (Exception ex) {
            Utils.Callback.printOutput(ex.toString());
        }
    }

    private void checkServiceSideBatchCheckSupport() {
        String[] testResult = batchCheck(new String[0]);
        serverSideSupportBatchCheck = testResult != null;
        Utils.Callback.printOutput(String.format("Service-side RevSuit %s batch check!\r\n", serverSideSupportBatchCheck ? "support" : "unsupported"));
    }

    public String[] batchCheck(String[] payloads) {
        List<String> found = new ArrayList<>();
        try {
            JSONObject findDomainReq = new JSONObject();
            findDomainReq.put("rmis", cleanPayload(payloads));
            JSONObject foundRecords = JSONObject.parseObject(request("revsuit/api/record/rmi/batchFind", "POST", findDomainReq.toString()));
            foundRecords.getJSONArray("found").forEach(f -> found.add(appendBefore((String) f)));
            return found.toArray(new String[0]);
        } catch (Exception ex) {
            return null;
        }
    }

    private String[] cleanPayload(String[] payloads) {
        List<String> result = new ArrayList<>();
        for (int i = 0; i < payloads.length; i++) {
            String payload = payloads[i];
            result.add(payload.substring(payload.indexOf(rmiFlag)));
        }
        return result.toArray(new String[0]);
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
        return appendBefore(rmiFlag + "/" + Utils.GetRandomString(10));
    }

    public String appendBefore(String randomStr) {
        return rootRMIUrl + randomStr;
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
    public void close() {
    }

    @Override
    public int[] getSupportedPOCTypes() {
        return new int[]{IPOC.POC_TYPE_RMI};
    }
}
