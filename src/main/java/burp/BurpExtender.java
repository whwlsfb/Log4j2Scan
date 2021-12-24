package burp;

import burp.scanner.Log4j2Scanner;
import burp.ui.Log4j2ScanUIHandler;
import burp.utils.Utils;

import java.awt.*;
import java.io.PrintWriter;

public class BurpExtender implements IBurpExtender, IExtensionStateListener {

    public IExtensionHelpers helpers;
    public IBurpExtenderCallbacks callbacks;
    public PrintWriter stdout;
    public PrintWriter stderr;
    public String version = "0.10";
    public Log4j2ScanUIHandler uiHandler;
    public Log4j2Scanner scanner;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        Utils.Callback = this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);
        callbacks.setExtensionName("Log4j2Scan");
        this.stdout.println("Log4j2Scan v" + version);
        this.uiHandler = new Log4j2ScanUIHandler(this);
        callbacks.addSuiteTab(this.uiHandler);
        this.reloadScanner();
        callbacks.registerExtensionStateListener(this);
    }

    public void reloadScanner() {
        if (scanner != null) {
            scanner.close();
            callbacks.removeScannerCheck(scanner);
        }
        scanner = new Log4j2Scanner(this);
        callbacks.registerScannerCheck(scanner);
    }

    @Override
    public void extensionUnloaded() {
        if (scanner != null) {
            scanner.close();
            callbacks.removeScannerCheck(scanner);
        }
    }
}
