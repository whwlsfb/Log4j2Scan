# Log4j2Scan

> This tool is only for learning, research and self-examination. It should not be used for illegal purposes. All risks arising from the use of this tool have nothing to do with me!

> dnslog.cn is unable to access the interface from time to time due to the number of requests. If you are unable to scan, please try change dnslog platform from UI.

English | [简体中文](./README-zh_CN.md)

Log4j2 Remote Code Execution Vulnerability, Passive Scan Plugin for BurpSuite.

Support accurate hint vulnerability parameters, vulnerability location, support multi-dnslog platform extension, automatic ignore static files.

Vulnerability detection only supports the following types for now
- Url
- Cookie
- Header
- Body(x-www-form-urlencoded, json, xml, multipart)

# ChangeLog
### 2021/12/14
##### v0.9
1. add [GoDnslog](https://github.com/chennqqi/godnslog) backend, thx for [@54Pany](https://github.com/54Pany) .
2. add fuzz setting ui.
3. add poc setting ui.
4. add Body(json, xml, multipart) fuzz.
5. opt header guess-fuzz logic.
### 2021/12/13
##### v0.8.1
1. bypass dnslog.cn filter.
##### v0.8
1. add backend setting panel.
2. add [RevSuit](https://github.com/Li4n0/revsuit/)-DNS backend.
### 2021/12/13
##### v0.7
1. add [RevSuit](https://github.com/Li4n0/revsuit/)-RMI backend.
2. fix domain toLowerCase by server can't match issue.
### 2021/12/12
##### v0.6
1. add static-file ignore.
2. add mulit poc support.
3. add burpcollaborator dnslog backend,default use dnslog.cn.
### 2021/12/11
##### v0.5
1. add header fuzz.
##### v0.4
1. add rc1 patch bypass.

# Screenshot

![](screenshots/backends.png)

![](screenshots/ceye_backend.png)

![](screenshots/revsuit_rmi_backend.png)

![](screenshots/revsuit_dns_backend.png)

![](screenshots/godnslog_backend.png)

![](screenshots/poc_setting.png)

![](screenshots/fuzz_setting.png)

![](screenshots/detected.png)


# Acknowledgements
Some of the code in the plugin is borrowed from the following projects

https://github.com/pmiaowu/BurpShiroPassiveScan/
