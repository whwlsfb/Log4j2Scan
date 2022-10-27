# Log4j2Scan

> 本工具无攻击性，仅具有漏洞探测功能，且仅供学习研究自查使用，切勿用于非法用途，由使用该工具产生的一切风险均与本人无关！

> dnslog.cn由于请求人数过多，时有无法访问接口的问题，若出现无法扫描的情况时，请尝试通过菜单切换dnslog平台。

[English](./README.md) | 简体中文

该工具为被动扫描Log4j2漏洞CVE-2021-44228的BurpSuite插件，具有多DNSLog（后端）平台支持，支持异步并发检测、内网检测、延迟检测等功能。

# 编译
需要Maven、JDK 11.0或更高版本。
```
$ mvn package
```

## 安装方法

建议使用BurpSuite 2020或以上更高版本，低版本BurpSuite未经严格测试可能会产生未知异常，安装需导航至BurpSuite的`Extender->Extensions`界面，点击`Add`按钮，在弹出的窗口中点击`Select file ...`按钮，在文件打开页面中找到插件的jar文件，安装即可。

在安装、设置完成后推荐使用[vulfocus](https://vulfocus.cn/)测试靶场，或公开靶场：[http://d63bb2586.lab.aqlab.cn/](http://d63bb2586.lab.aqlab.cn/)测试插件是否工作正常。

在正常状况下，使用`DnslogCN`后端平台检测[http://d63bb2586.lab.aqlab.cn/](http://d63bb2586.lab.aqlab.cn/)靶场的登录接口，从检测开始至首次获取DNSLog结果，用时应在5秒以内。

## 插件特性说明

本插件相较于传统Log4j检测插件有几点特殊功能，此处单独说明。

### 并发

本插件在开启`Enable Ex-request`设置项后将会支持并发检测，并发量目前默认为`10`线程并发，后续将会开发并发相关的开启/关闭、并发量的设置界面。

### 内网检测

本插件的内网检测仅支持`RevSuitRMI`的后端平台，即基于RMI协议的TCP回连机制，需要在内网环境中访问性较好的服务器中搭建`revsuit`服务，设置相关参数后即可使用。

### 延迟检测

由于部分后端平台在接收到漏洞服务器发来的请求后并不会立即更新至Dnslog记录中、或漏洞服务器的网络状态导致的网络延迟，导致在旧版本的Log4j2Scan插件中，常常会出现插件无法正常检测到实际存在的漏洞，而在稍后登录相关平台的网站页面中才能看到Dnslog的查询记录。

在`v0.13`更新中，对该情况做了特殊处理，当首次查询DNSLog记录未能检测到漏洞的检测点，将会保存至插件缓存。同时为了避免条目过多导致内存泄漏，目前缓存时间设置为5分钟，在这5分钟之内，插件将会每30s查询一次后端平台，重新检查漏洞点是否触发，并在检测到触发后在BurpSuite中生成漏洞条目，以避免大部分情况下的漏报问题。

## 使用

该插件安装完成后，建议根据需要修改插件设置，插件设置位于BurpSuite的Log4j2Scan选项卡，本插件默认使用BurpSuite内嵌的后端平台`BurpCollaborator`，建议切换至`DnslogCN`或`DigPm`，扫描发现的漏洞将会生成漏洞条目出现在BurpSuite首页的`Issue activity`中。

本插件具有如下设置项：
### Backend

该设置界面用户修改当前使用的后端平台，目前支持的平台如下表所示

| 平台名称         | 相关地址                             | 需要设置 | 需要自建服务 |
| ------------------ | -------------------------------------- | ---------- | -------------- |
| BurpCollaborator | /                                    | ×<br />     | ×           |
| DnslogCN         | http://dnslog.cn/                    | ×<br />     | ×           |
| Ceye             | http://ceye.io/                      | √       | ×           |
| RevSuitDNS       | https://github.com/Li4n0/revsuit     | √       | √           |
| RevSuitRMI       | https://github.com/Li4n0/revsuit     | √       | √           |
| GoDnslog         | https://github.com/chennqqi/godnslog | √       | √           |
| DigPm            | https://dig.pm/                      | ×<br />     | ×           |

### POC

设置启用的POC类型，根据WAF拦截情况与补丁绕过提供了多种POC类型，但是设置启用的数量过多将会导致流量激增、检测速度变慢。

### Fuzz
修改模糊测试的相关配置。

#### Fuzz Mode

修改模糊测试的测试模式，测试模式分为两种，`EachFuzz`与`Crazy`，默认为`EachFuzz`，两者区别如下。

| 模式     | 优点                                                                    | 缺点               |
| ---------- | ------------------------------------------------------------------------- | -------------------- |
| EachFuzz | 对请求中的所有参数进行单独检测，准确度最高                              | 请求流量较大       |
| Crazy    | 同时对请求中的所有参数进行Fuzz，一个POC将只请求一次，可显著降低网络压力 | 有较大几率发生漏报 |

#### Scan Mode

修改扫描的触发机制，分为两种`Passive`、`Active`，默认为`Passive`，两者区别如下。

| 模式    | 描述                                                                                                                        |
| --------- | ----------------------------------------------------------------------------------------------------------------------------- |
| Passive | 使用BurpSuite的被动扫描机制，当流量经过BurpSuite时，会自动转发至插件内，在筛选掉静态资源地址后进行扫描。                    |
| Active  | 使用BurpSuite的主动扫描机制和扫描器的专属扫描菜单，当用户在任意请求上右单击鼠标，在菜单中选择<br />`Extensions`->`Log4j2Scan`->`Send to Log4j2Scan`即可调用插件进行扫描。<br /> |

建议日常设置为`Active`，仅在人工判断请求为漏洞常见特征时，再发送至插件进行扫描，以降低出现**未授权攻击**的可能性。

#### Enable Ex-request

开启插件自实现的POC请求机制（强烈建议开启），在开启该选项的情况下，将会支持并发检测，并且将不再会使用BurpSuite提供的API发送请求（在Logger选项卡中将没有请求记录）以绕过其无法设置超时时间的限制，并在发送完POC请求后不会等待服务端响应，大幅提升检测速度。

#### Fuzz漏洞点设置

| 设置项                       | 说明                                                      | 默认开启 |
| ------------------------------ | ----------------------------------------------------------- | ---------- |
| Enable Header Fuzz           | 是否开启对Header中的参数进行测试。                        | 是       |
| Enable Url Fuzz              | 是否开启对URL中的参数进行测试。                           | 是       |
| Enable Cookie Fuzz<br />         | 是否开启对Cookie中的参数进行测试。                        | 是       |
| Enable Body Fuzz<br />           | 是否开启对Body中的参数进行测试。                          | 是       |
| Enable Body-Form Fuzz<br />      | 是否开启对Form型的Body中的参数进行测试。                  | 是       |
| Enable Body-Json Fuzz<br />      | 是否开启对Json型的Body中的参数进行测试。                  | 是       |
| Enable Body-Xml Fuzz<br />       | 是否开启对Xml型的Body中的参数进行测试。                   | 是       |
| Enable Body-Multipart Fuzz<br /> | 是否开启对Multipart型的Body中的参数进行测试。             | 是       |
| Enable Bad-Json Fuzz<br />       | 是否开启使用包含POC的语法错误的Json放置在Body中进行测试。 | 否       |

# 效果截图

![](screenshots/backends.png)

![](screenshots/ceye_backend.png)

![](screenshots/revsuit_rmi_backend.png)

![](screenshots/revsuit_dns_backend.png)

![](screenshots/godnslog_backend.png)

![](screenshots/poc_setting.png)

![](screenshots/fuzz_setting.png)

![](screenshots/detected.png)


# 鸣谢
插件中部分代码借鉴于以下项目

https://github.com/pmiaowu/BurpShiroPassiveScan/
