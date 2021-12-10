package burp.dnslog;

public interface IDnslog {
    String getName();

    String getNewDomain();

    boolean CheckResult(String domain);

    boolean getState();
}