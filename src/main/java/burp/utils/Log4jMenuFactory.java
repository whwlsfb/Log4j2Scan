package burp.utils;

import burp.*;

import javax.swing.*;
import java.util.ArrayList;
import java.util.List;

public class Log4jMenuFactory implements IContextMenuFactory {

    private BurpExtender parent;

    public Log4jMenuFactory(BurpExtender parent) {
        this.parent = parent;
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        ArrayList<JMenuItem> menus = new ArrayList<>();
        JMenuItem menu1 = new JMenuItem("Send to Log4jScan");
        menu1.addActionListener(e -> {
            IHttpRequestResponse[] reqs = invocation.getSelectedMessages();
            for (IHttpRequestResponse req : reqs) {
                new Thread(() -> {
                    List<IScanIssue> issues = parent.scanner.doActiveScan(req, null);
                    if (issues != null) {
                        for (IScanIssue issue : issues) {
                            parent.callbacks.addScanIssue(issue);
                        }
                    }
                }).start();
            }
        });
        menus.add(menu1);
        return menus;
    }
}
