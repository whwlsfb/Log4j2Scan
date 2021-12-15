package burp.utils;

public class ParamReplace {
    public int Start;
    public int End;
    public String Payload;

    public ParamReplace(int start, int end, String payload) {
        this.Start = start;
        this.End = end;
        this.Payload = payload;
    }
}
