package burp.backend.platform;

import burp.backend.IBackend;
import burp.poc.IPOC;
import burp.utils.HttpUtils;
import burp.utils.Utils;
import okhttp3.FormBody;
import okhttp3.OkHttpClient;
import okhttp3.Response;
import org.json.JSONArray;
import org.json.JSONObject;

import java.util.concurrent.TimeUnit;

import static burp.utils.HttpUtils.GetDefaultRequest;


public class DigPm implements IBackend {
    OkHttpClient client = new OkHttpClient().newBuilder().
            connectTimeout(3000, TimeUnit.SECONDS).
            callTimeout(3000, TimeUnit.SECONDS).build();
    String platformUrl = "https://dig.pm/";
    String rootDomain = "";
    String userDomain = "";
    String token = "";
    String cache = "";

    public DigPm() {
        this.initDomain();
    }

    private void initDomain() {
        String respStr = null;
        try {
            Utils.Callback.printOutput("get domain...");
            Response resp = client.newCall(GetDefaultRequest(platformUrl + "get_domain?t=0." + Math.abs(Utils.getRandomLong())).build()).execute();
            respStr = resp.body().string();
            String[] rootDomains = new JSONArray(respStr).toList().toArray(new String[0]);
            rootDomain = rootDomains[0];
            resp = client.newCall(GetDefaultRequest(platformUrl + "get_sub_domain").post(new FormBody.Builder().add("mainDomain", rootDomains[0]).build()).build()).execute();
            respStr = resp.body().string();
            JSONObject jobj = new JSONObject(respStr);
            userDomain = (String) jobj.get("subDomain");
            token = (String) jobj.get("token");
            userDomain = userDomain.endsWith(".") ? userDomain.substring(0, userDomain.length() - 1) : userDomain;
            Utils.Callback.printOutput(String.format("Domain: %s.%s", userDomain, rootDomain));
            Utils.Callback.printOutput(String.format("ShareLink: https://dig.pm/?mainDomain=%s&token=%s&subDomain=%s", rootDomain, token, userDomain));
        } catch (Exception ex) {
            Utils.Callback.printError("initDomain failed: " + ex.getMessage());
            if (respStr != null)
                Utils.Callback.printError("RespStr: " + respStr);
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
        return "Dig.pm";
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
                            add("subDomain", userDomain).
                            add("mainDomain", rootDomain).
                            add("token", token)
                            .build()).build()).execute();
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
