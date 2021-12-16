package burp.backend.platform;

import burp.backend.IBackend;
import burp.poc.IPOC;
import burp.utils.Config;
import burp.utils.HttpUtils;
import burp.utils.Utils;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import okhttp3.OkHttpClient;
import okhttp3.Response;

import java.math.BigInteger;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.TimeUnit;


public class GoDnslog implements IBackend {
    OkHttpClient client = new OkHttpClient().newBuilder().
            connectTimeout(3000, TimeUnit.SECONDS).
            callTimeout(3000, TimeUnit.SECONDS).build();
    String rootDomain;
    String token;

    public GoDnslog() {
        this.rootDomain = Config.get(Config.GODNSLOG_IDENTIFIER);
        this.token = Config.get(Config.GODNSLOG_TOKEN);
    }

    @Override
    public boolean supportBatchCheck() {
        return false;
    }

    public String getSign(String urlParam) {
        StringBuilder hashBuilder = new StringBuilder();
        Map<String, String> paraMap = new TreeMap<>();
        String[] params = urlParam.split("&");
        for (String s : params) {
            int index = s.indexOf("=");
            if (index != -1) {
                paraMap.put(s.substring(0, index), s.substring(index + 1));
            }
        }
        for (Map.Entry<String, String> entry : paraMap.entrySet()) {
            hashBuilder.append(entry.getValue());
        }
        String hash = hashBuilder.toString();
        hash += token;
        return new BigInteger(1, Utils.MD5(hash.getBytes())).toString(16);
    }

    @Override
    public String getName() {
        return "github.com/chennqqi/godnslog";
    }

    @Override
    public String getNewPayload() {
        return Utils.getCurrentTimeMillis() + Utils.GetRandomString(5).toLowerCase() + "." + rootDomain;
    }

    @Override
    public String[] batchCheck(String[] payloads) {
        return new String[0];
    }

    @Override
    public boolean CheckResult(String domain) {
        String timeStamp = String.valueOf(System.currentTimeMillis() / 1000);
        String query = domain.toLowerCase().substring(0, domain.indexOf("."));
        String hash = getSign("q=" + query + "&t=" + timeStamp + "&blur=1");
        try {
            Response resp = client.newCall(HttpUtils.GetDefaultRequest("http://" + rootDomain + "/data/dns?q=" + query + "&t=" + timeStamp + "&blur=1" + "&hash=" + hash).build()).execute();
            JSONObject jObj = JSONObject.parseObject(resp.body().string().toLowerCase());
            if (jObj.containsKey("result")) {
                return (((JSONArray) jObj.get("result")).size() > 0);
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
