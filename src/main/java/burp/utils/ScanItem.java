package burp.utils;

import burp.IHttpRequestResponse;
import burp.IParameter;

public class ScanItem {
    public ScanItem(IParameter param, IHttpRequestResponse tmpreq, byte[] rawRequest) {
        this.Param = param;
        this.TmpRequest = tmpreq;
        this.RawRequest = rawRequest;
    }

    public ScanItem(String headerName, IHttpRequestResponse tmpreq, byte[] rawRequest) {
        this.IsHeader = true;
        this.HeaderName = headerName;
        this.TmpRequest = tmpreq;
        this.RawRequest = rawRequest;
    }

    public String HeaderName;
    public boolean IsHeader;
    public IParameter Param;
    public IHttpRequestResponse TmpRequest;
    public byte[] RawRequest;
}
