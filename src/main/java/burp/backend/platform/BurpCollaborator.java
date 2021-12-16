package burp.backend.platform;

import burp.IBurpCollaboratorClientContext;
import burp.backend.IBackend;
import burp.poc.IPOC;
import burp.utils.Utils;

public class BurpCollaborator implements IBackend {
    IBurpCollaboratorClientContext bcContext;

    public BurpCollaborator() {
        bcContext = Utils.Callback.createBurpCollaboratorClientContext();
    }

    @Override
    public boolean supportBatchCheck() {
        return false;
    }

    @Override
    public String getName() {
        return "BurpCollaborator";
    }
    @Override
    public String[] batchCheck(String[] payloads) {
        return new String[0];
    }
    @Override
    public String getNewPayload() {
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
    public boolean flushCache(int count) {
        return flushCache();
    }

    @Override
    public boolean getState() {
        return true;
    }

    @Override
    public int[] getSupportedPOCTypes() {
        return new int[]{IPOC.POC_TYPE_LDAP, IPOC.POC_TYPE_RMI};
    }

    @Override
    public void close() {
    }
}
