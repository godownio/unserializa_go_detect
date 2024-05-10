# 毕设

前言：距离上次的JAVA网上书城（完全够毕设工作量，毕设做JAVA可以看https://godownio.github.io/2023/05/20/java-shu-cheng-kai-fa-quan-liu-cheng/ ）已经过去了一年了。花了半年考了个研，专业第二秒了，折合分421.5，数学爆砍126，但是我越发觉得读研是个傻逼干的事，纯没本事，哭了。不说了，转到正题。

本毕设fork自https://github.com/evepupil/ip_package 。仿Wireshark纯抓包工具，加了个模糊匹配字节询问GPT是否为恶意数据。

成品图如下：

* 恶意流量检测模块：

![718010841cfdfab5a4b8d573e56bc2ab](https://typora-202017030217.oss-cn-beijing.aliyuncs.com/typora/718010841cfdfab5a4b8d573e56bc2ab.png)

![08cfc52f4e4aae7b92ebca557f96b2dc](https://typora-202017030217.oss-cn-beijing.aliyuncs.com/typora/08cfc52f4e4aae7b92ebca557f96b2dc.png)

* 全流量模块

![image-20240506163017511](https://typora-202017030217.oss-cn-beijing.aliyuncs.com/typora/image-20240506163017511.png)



加个狗屎UI花了三倍以上的代码和时间。

创新点：go本身线程安全（作为常驻WAF本身不易遭到攻击），gopacket基于Npcap，Winpcap升级版，goroutine协程效率高，资源消耗低。LLM判结果，方便且更新快。

## 使用手册

本工具已将阿里qwen LLM SDK拖到本地，请前往qwen_model.go修改ChatQWenModel为自己需要的LLM

```go
ChatQWenModel = "qwen-turbo"
```

计费如下（越贵越慢，但是更准）：

![image-20240506164052032](https://typora-202017030217.oss-cn-beijing.aliyuncs.com/typora/image-20240506164052032.png)

在http_copy.go#queryAI()把apiKey修改为自己的灵积API，请前往https://dashscope.console.aliyun.com/apiKey

环境使用go 1.21.9，在1.1+都OK，c++环境使用TDM-GCC，需要安装fyne：

```shell
go get fyne.io/fyne/v2
```

点击`开始/切换`，一般选择Loopback做测试，Loopback是安装wireshark所带的本地环回地址网卡，监测以太网是无法监测到环回地址流量的。

![image-20240506164734028](https://typora-202017030217.oss-cn-beijing.aliyuncs.com/typora/image-20240506164734028.png)

同理，全流量也选择网卡即可。

* 全流量模式：可以使用菜单上所有功能，如过滤、排序、捕获等（严格模式：只接收来自IP包发往本机的数据包；混杂模式：接收发往其他主机，流经过本地的数据包）
* HTTP流量分析模式：可以使用暂停继续，发送数据包功能。

在runRequest()修改targetStrings匹配规则

```go
targetStrings := []string{"rememberMe", "rO0A", "@type", "aced"}
```

还有个BUG，我在AI回答每隔31个字符插入一个回车，但是总是换行混乱。

```go
func insertNewlineEveryNChars(s string, n int) string {
    var result string
    for i, r := range s {
       result += string(r)
       if (i+1)%n == 0 && i+1 < len(s) {
          result += "\n"
       }
    }
    return result
}
```

因为无法加入CA证书，所以暂时还不知道怎么分析加密的HTTPS流量，交给你们了。



## 概述

使用了embed打包静态数据，app.go#Run()函数为Fyne的阻塞函数，应用程序运行的主函数。

LoadMenus()加载菜单数据，在里面的切换响应的回调函数SetAllContainer(w, A)设置了列头。

相应的SetContainer(w, A)设置了另一个Container。全流量抓包逻辑在GetPkg()，HTTP抓包逻辑在GetHTTPPkg()。GetPkg()逻辑很好理解，一层一层跟下去看代码就行了

重点是GetHTTPPkg()

```go
func GetHTTPPkg(ctx context.Context, device_str string) {
    defer util.Run()()
    handle, err := pcap.OpenLive(device_str, snapshot_len, Promiscuous, timeout)
    if err != nil {
       log.Fatal(err)
    }

    if err := handle.SetBPFFilter(*filter); err != nil {
       log.Fatal(err)
    }
    No := 1
    // Set up assembly
    streamFactory := &httpStreamFactory{}
    streamPool := tcpassembly.NewStreamPool(streamFactory)
    assembler := tcpassembly.NewAssembler(streamPool)

    log.Println("reading in packets")
    // Read in packets, pass to assembler.
    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    packets := packetSource.Packets()
    ticker := time.Tick(time.Minute)
    for {
       if Interupt == false {
          select {
          case packet := <-packets:
             // A nil packet indicates the end of a pcap file.
             if packet == nil {
                return
             }
             if *logAllPackets {
                log.Println(packet)
             }
             if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
                log.Println("Unusable packet")
                continue
             }
             tcp := packet.TransportLayer().(*layers.TCP)
             assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)
          case <-ticker:
             // Every minute, flush connections that haven't seen activity in the past 2 minutes.
             assembler.FlushOlderThan(time.Now().Add(time.Minute * -2))
          }
       }
       No++
    }
}
```

在`assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)`进行了TCP重组，防止TCP分片把HTTP数据包分呈好几片，看不了一点。

在调用AssembelWithTimestamp()时，内置函数会自动调用(h *httpStreamFactory) New()函数处理HTTP流量

重构一下New函数为自己的处理逻辑，比如装入一个新struct，在GUI展示的时候就很好办了。

```go
func (h *httpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
    hstream := &httpStream{
       net:       net,
       transport: transport,
       r:         tcpreader.NewReaderStream(),
    }

    src, dst := transport.Endpoints()
    if fmt.Sprintf("%v", src) == "80" {
       go hstream.runResponse() // 处理响应
    } else if fmt.Sprintf("%v", dst) == "80" {
       go hstream.runRequest() // 处理请求
    } else if fmt.Sprintf("%v", dst) == "443" {
       go hstream.runRequests() // 处理HTTPS请求
    } else {
       go hstream.run() // 处理其他流量
    }
    //fmt.Println(pkgData)
    return &hstream.r
}
```





### main.go

首先，main.go进行了字体初始化，并调用了应用程序的主程序进行阻塞响应。

在Run()对Fyne窗口进行了一系列设置。可以先忽略带HTTP函数的内容，因为基本都是函数复用。

LoadMenus加载菜单，LoadLayers()为点击数据包的如下内容，对LayersData数据做展示，

![image-20240506170807012](https://typora-202017030217.oss-cn-beijing.aliyuncs.com/typora/image-20240506170807012.png)

PkgInfo为点击数据包的如下内容，使用NewTable进行展示。

![image-20240506170940397](https://typora-202017030217.oss-cn-beijing.aliyuncs.com/typora/image-20240506170940397.png)

Monitor为右下角的网卡信息。



