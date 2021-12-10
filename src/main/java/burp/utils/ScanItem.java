package burp.utils;

import burp.IHttpRequestResponse;
import burp.IParameter;

public class ScanItem {
    public ScanItem(IParameter param, IHttpRequestResponse tmpreq) {
        this.Param = param;
        this.TmpRequest = tmpreq;
    }

    public IParameter Param;
    public IHttpRequestResponse TmpRequest;
}
