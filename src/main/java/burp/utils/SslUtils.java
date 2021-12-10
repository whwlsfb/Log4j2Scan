package burp.utils;

import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.*;

public class SslUtils {
    public static SSLSocketFactory getTrustAll() {
        return getTrustAll("SSL");
    }

    public static SSLSocketFactory getTrustAll(String sslVersion) {
        try {
            SSLContext sslContext = SSLContext.getInstance(sslVersion);
            sslContext.init(null, new TrustManager[]{new TrustAll()}, new SecureRandom());
            return sslContext.getSocketFactory();
        } catch (Exception ex) {
            return null;
        }
    }

    public static class TrustAll implements TrustManager, X509TrustManager {
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[]{};
        }

        public boolean isServerTrusted(X509Certificate[] certs) {
            return true;
        }

        public boolean isClientTrusted(X509Certificate[] certs) {
            return true;
        }

        public void checkServerTrusted(X509Certificate[] certs, String authType)
                throws CertificateException {
            return;
        }

        public void checkClientTrusted(X509Certificate[] certs, String authType)
                throws CertificateException {
            return;
        }
    }
}
