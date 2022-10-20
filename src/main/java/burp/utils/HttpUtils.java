package burp.utils;

import burp.BurpExtender;
import burp.IHttpService;
import burp.IRequestInfo;
import okhttp3.*;
import okhttp3.internal.http.HttpMethod;

import java.io.PrintStream;
import java.util.Arrays;
import java.util.Calendar;
import java.util.List;
import java.util.concurrent.TimeUnit;

public class HttpUtils {
    public static CacheControl NoCache = new CacheControl.Builder().noCache().noStore().build();
    static OkHttpClient client = new OkHttpClient().newBuilder().
            connectTimeout(3000, TimeUnit.MILLISECONDS).
            callTimeout(500, TimeUnit.MILLISECONDS).build();

    public static Request.Builder GetDefaultRequest(String url) {
        int fakeFirefoxVersion = Utils.GetRandomNumber(45, 94 + Calendar.getInstance().get(Calendar.YEAR) - 2021);
        Request.Builder requestBuilder = new Request.Builder()
                .url(url);
        requestBuilder.header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:" + fakeFirefoxVersion + ".0) Gecko/20100101 Firefox/" + fakeFirefoxVersion + ".0");
        return requestBuilder.cacheControl(NoCache);
    }

    public static String getUrlFileExt(String url) {
        String pureUrl = url.substring(0, url.contains("?") ? url.indexOf("?") : url.length());
        return (pureUrl.lastIndexOf(".") > -1 ? pureUrl.substring(pureUrl.lastIndexOf(".") + 1) : "").toLowerCase();
    }

    public static void RawRequest(IHttpService httpService, byte[] rawRequest, IRequestInfo req) {
        byte[] body = Arrays.copyOfRange(rawRequest, req.getBodyOffset(), rawRequest.length);
        List<String> headers = req.getHeaders();
        Request.Builder requestBuilder = new Request.Builder()
                .url(req.getUrl());
        for (int i = 1; i < headers.size(); i++) {
            HttpHeader header = new HttpHeader(headers.get(i));
            requestBuilder.header(header.Name, header.Value);
        }
        if(HttpMethod.permitsRequestBody(req.getMethod())) {
            requestBuilder.method(req.getMethod(), RequestBody.create(body));
        } else {
            requestBuilder.method(req.getMethod(), null);
        }
        requestBuilder.cacheControl(NoCache);
        try {
            client.newCall(requestBuilder.build()).execute();
        } catch (Exception ex) {
            if (ex.getMessage().contains("timout")) {
                return;
            }
            ex.printStackTrace(new PrintStream(Utils.Callback.getStderr()));
        }
    }
}
