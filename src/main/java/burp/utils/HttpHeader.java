package burp.utils;

public class HttpHeader {
    public String Name;
    public String Value = "";

    public HttpHeader(String src) {
        int headerLength = src.indexOf(':');
        if (headerLength > -1) {
            Name = src.substring(0, headerLength);
            Value = src.substring(headerLength + 1).trim();
        } else {
            Name = src;
        }
    }

    @Override
    public String toString() {
        return String.format("%s: %s", Name, Value);
    }
}
