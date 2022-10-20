package burp.utils;

import burp.IHttpRequestResponse;
import burp.IParameter;
import burp.IRequestInfo;

public class ScanItem {
    public ScanItem(IParameter param, IHttpRequestResponse tmpreq, IHttpRequestResponse baseReq, byte[] rawRequest) {
        this.Param = param;
        this.TmpRequest = tmpreq;
        this.RawRequest = rawRequest;
        this.BaseRequest = baseReq;
    }

    public ScanItem(String headerName, IHttpRequestResponse tmpreq, IHttpRequestResponse baseReq, byte[] rawRequest) {
        this.IsHeader = true;
        this.HeaderName = headerName;
        this.TmpRequest = tmpreq;
        this.RawRequest = rawRequest;
        this.BaseRequest = baseReq;
    }

    public String HeaderName;
    public boolean IsHeader;
    public IParameter Param;
    public IRequestInfo RequestInfo;
    public IHttpRequestResponse TmpRequest;
    public IHttpRequestResponse BaseRequest;
    public byte[] RawRequest;
}
