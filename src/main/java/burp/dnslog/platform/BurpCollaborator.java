package burp.dnslog.platform;

import burp.IBurpCollaboratorClientContext;
import burp.dnslog.IDnslog;
import burp.utils.Utils;

public class BurpCollaborator implements IDnslog {
    IBurpCollaboratorClientContext bcContext;

    public BurpCollaborator() {
        bcContext = Utils.Callback.createBurpCollaboratorClientContext();
    }

    @Override
    public String getName() {
        return "BurpCollaborator";
    }

    @Override
    public String getNewDomain() {
        return bcContext.generatePayload(true);
    }

    @Override
    public boolean CheckResult(String domain) {
        return !bcContext.fetchCollaboratorInteractionsFor(domain).isEmpty();
    }

    @Override
    public boolean flushCache() {
        return true;
    }

    @Override
    public boolean getState() {
        return true;
    }
}
