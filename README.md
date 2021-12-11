# Log4j2Scan

> 本工具仅供学习研究自查使用，切勿用于非法用途，由使用该工具产生的一切风险均与本人无关！

> dnslog.cn由于请求人数过多，时有无法访问接口的问题，若出现无法扫描的情况时，请确认插件日志中是否提示Dnslog加载成功

Log4j2 远程代码执行漏洞，BurpSuite被动扫描插件。

v0.4版本已加入RC1补丁的绕过poc。

暂只支持Url、Cookie、POST(x-www-form-urlencoded)类型的参数fuzz。

![](screenshots/detected.png)



# 鸣谢
插件中部分代码借鉴于以下项目

https://github.com/pmiaowu/BurpShiroPassiveScan/
