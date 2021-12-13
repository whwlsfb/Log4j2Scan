# Log4j2Scan

> This tool is only for learning, research and self-examination. It should not be used for illegal purposes. All risks arising from the use of this tool have nothing to do with me!

> dnslog.cn is unable to access the interface from time to time due to the number of requests. If you are unable to scan, please check whether the plug-in log indicates that the Dnslog is loaded successfully, or set the dnslog to ceye.io according to the method below

English | [简体中文](./README-zh_CN.md)

Log4j2 Remote Code Execution Vulnerability, BurpSuite Passive Scan Plugin.

Support accurate hint vulnerability parameters, vulnerability location, support multi-dnslog platform extension, automatic ignore static files.

Vulnerability detection only supports the following types for now
- Url
- Cookie
- Header
- Body(x-www-form-urlencoded)

# ChangeLog
### 2021/12/13
##### v0.7
1. add [RevSuit](https://github.com/Li4n0/revsuit/)-RMI backend。
2. fix domain toLowerCase by server can't match issue。
### 2021/12/12
##### v0.6
1. add static-file ignore.
2. add mulit poc support.
3. add burpcollaborator dnslog backend,default use dnslog.cn。
### 2021/12/11
##### v0.5
1. add header fuzz。
##### v0.4
1. add rc1 patch bypass。

# Screenshot

![](screenshots/detected.png)


# Modify Dnslog platform

Because there is not much time to develop the UI, you can use the following method to switch the Dnslog platform to `ceye.io` manually if you have the need to modify the dnslog platform temporarily first

1. Download the source code and open it with any IDE.
2. Ceye.java needs to modify the values of "rootDomain" and "token", which correspond to the Identifier and API Token in ceye's profile page.
3. Log4j2Scanner.java needs to be modified from `this.backend = new DnslogCN();` to `this.backend = new Ceye();`.
4. Repackage the project using `mvn package`.

# Acknowledgements
Some of the code in the plugin is borrowed from the following projects

https://github.com/pmiaowu/BurpShiroPassiveScan/
