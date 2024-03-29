package burp.utils;

import burp.*;
import okhttp3.*;
import okhttp3.internal.http.HttpMethod;
import org.jetbrains.annotations.NotNull;

import javax.net.ssl.*;
import java.io.PrintStream;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Calendar;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.locks.ReentrantLock;

public class HttpUtils {
    public static CacheControl NoCache = new CacheControl.Builder().noCache().noStore().build();
    static OkHttpClient client = configureToIgnoreCertificate(new OkHttpClient().newBuilder().
            hostnameVerifier((hostname, session) -> true).
            connectTimeout(3000, TimeUnit.MILLISECONDS).
            callTimeout(500, TimeUnit.MILLISECONDS)).
            build();

    private static OkHttpClient.Builder configureToIgnoreCertificate(OkHttpClient.Builder builder) {
        try {

            // Create a trust manager that does not validate certificate chains
            final TrustManager[] trustAllCerts = new TrustManager[]{
                    new X509TrustManager() {
                        @Override
                        public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType)
                                throws CertificateException {
                        }

                        @Override
                        public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType)
                                throws CertificateException {
                        }

                        @Override
                        public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                            return new java.security.cert.X509Certificate[]{};
                        }
                    }
            };

            // Install the all-trusting trust manager
            final SSLContext sslContext = SSLContext.getInstance("SSL");
            sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
            // Create an ssl socket factory with our all-trusting manager
            final SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

            builder.sslSocketFactory(sslSocketFactory, (X509TrustManager) trustAllCerts[0]);
            builder.hostnameVerifier(new HostnameVerifier() {
                @Override
                public boolean verify(String hostname, SSLSession session) {
                    return true;
                }
            });
        } catch (Exception e) {
        }
        return builder;
    }

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

    private static ThreadPoolExecutor executor;
    private static final ReentrantLock mainLock = new ReentrantLock();

    public static void RawRequest(IHttpService httpService, byte[] rawRequest, IRequestInfo req) {
        mainLock.lock();
        executor.submit(() -> _rawRequest(httpService, rawRequest, req));
        mainLock.unlock();
    }

    public static void waitForRequestFinish(int requestCount) throws InterruptedException {
        mainLock.lock();
        executor.shutdown();
        executor.awaitTermination(requestCount * 500L, TimeUnit.MILLISECONDS);
        resetTaskPool();
        mainLock.unlock();
    }

    private static void _rawRequest(IHttpService httpService, byte[] rawRequest, IRequestInfo req) {
        byte[] body = Arrays.copyOfRange(rawRequest, req.getBodyOffset(), rawRequest.length);
        List<String> headers = req.getHeaders();
        Request.Builder requestBuilder = new Request.Builder()
                .url(req.getUrl());
        for (int i = 1; i < headers.size(); i++) {
            HttpHeader header = new HttpHeader(headers.get(i));
            requestBuilder.header(header.Name, header.Value);
        }
        if (HttpMethod.permitsRequestBody(req.getMethod())) {
            requestBuilder.method(req.getMethod(), RequestBody.create(body));
        } else {
            requestBuilder.method(req.getMethod(), null);
        }
        requestBuilder.cacheControl(NoCache);
        try {
            client.newCall(requestBuilder.build()).execute();
        } catch (Exception ex) {
            if (ex.getMessage().contains("timeout")) {
                return;
            }
            (new PrintStream(Utils.Callback.getStderr())).println(ex.getMessage());
        }
    }

    public static void resetTaskPool() {
        executor = new ThreadPoolExecutor(10, 10, 5L, TimeUnit.SECONDS, new LinkedBlockingQueue<>());
    }

    static {
        resetTaskPool();
    }
}
