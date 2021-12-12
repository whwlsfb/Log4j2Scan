package burp.backend;

public interface IBackend {
    String getName();

    String getNewPayload();

    boolean CheckResult(String payload);

    boolean flushCache();

    boolean flushCache(int count);

    boolean getState();

    int[] getSupportedPOCTypes();
}