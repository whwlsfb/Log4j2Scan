package burp.utils;

import burp.IHttpRequestResponse;
import burp.IParameter;

public class ScanItem {
    public ScanItem(IParameter param, IHttpRequestResponse tmpreq) {
        this.Param = param;
        this.TmpRequest = tmpreq;
    }

    public ScanItem(String headerName, IHttpRequestResponse tmpreq) {
        this.IsHeader = true;
        this.HeaderName = headerName;
        this.TmpRequest = tmpreq;
    }

    public String HeaderName;
    public boolean IsHeader;
    public IParameter Param;
    public IHttpRequestResponse TmpRequest;
}
