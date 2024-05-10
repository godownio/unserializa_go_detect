package ip

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"github.com/xinggaoya/qwen-sdk/qwen"
	"github.com/xinggaoya/qwen-sdk/qwenmodel"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/google/gopacket"
	"github.com/google/gopacket/examples/util"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

var iface = "\\Device\\NPF_Loopback"
var fname = flag.String("r", "", "Filename to read from, overrides -i")
var snaplen = flag.Int("s", 1600, "SnapLen for pcap packet capture")
var filter = flag.String("f", "tcp and port 80", "BPF filter for pcap")
var logAllPackets = flag.Bool("v", false, "Logs every packet in great detail")

// 使用tcpassembly.StreamFactory和tcpassembly.Stream接口构建一个简单的HTTP请求解析器
type httpStreamFactory struct{}

var httpRowMutex sync.Mutex

type httpStream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
	requestBody    *bytes.Buffer // 保存请求的 body 内容
	responseBody   *bytes.Buffer // 保存响应的 body 内容
} // 新建一个流，根据来源和目的地端口分别处理请求和响应。

// New 创建一个新的HTTP流。
// 参数:
//
//	net: 表示网络流的gopacket.Flow。
//	transport: 表示传输流的gopacket.Flow。
//
// 返回值:
//
//	返回一个实现了tcpassembly.Stream接口的指针。
var HTTPRowList = HTTPRow{
	Info:     "暂无",
	AIanwser: "暂无",
}

var containsAcEd = false

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

// 读取并日志记录所有请求和响应的数据。
func (h *httpStream) runRequests() {
	reader := bufio.NewReader(&h.r)

	defer tcpreader.DiscardBytesToEOF(reader)

	log.Println(h.net, h.transport)

	for {
		data := make([]byte, 1600)
		n, err := reader.Read(data)
		if err == io.EOF {
			return
		}
		log.Printf("[% x]", data[:n])

	}
}

// 通用的流量处理函数。
func (h *httpStream) run() {
	reader := bufio.NewReader(&h.r)
	defer tcpreader.DiscardBytesToEOF(reader)

	log.Println(h.net, h.transport)
	for {
		data := make([]byte, 1600)
		n, err := reader.Read(data)
		if err == io.EOF {
			return
		}
		log.Printf("[%s]", string(data[:n]))
	}

}

// 打印HTTP请求或响应的头部。
func printHeader(h http.Header) {
	for k, v := range h {
		fmt.Println(k, ":", v[0])
	}
}

// 处理HTTP响应。
func (h *httpStream) runResponse() {
	buf := bufio.NewReader(&h.r)
	defer tcpreader.DiscardBytesToEOF(buf)

	h.responseBody = bytes.NewBuffer(nil) // 初始化 response body 缓冲区

	for {
		resp, err := http.ReadResponse(buf, nil)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return
		} else if err != nil {
			log.Println("Error reading stream", h.net, h.transport, ":", err)
			return
		} else {
			// 读取响应 body 内容并保存到缓冲区
			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				log.Println("Error reading response body:", err)
				return
			}
			h.responseBody.Write(body)
			response := printResponse(resp, h)
			//fmt.Println(response)
			HTTPRowList.Responsition = response
			pattern := "(?i)ladp|rmi" //匹配外联服务
			re, err := regexp.Compile(pattern)
			var result string
			//fmt.Println(HTTPRowList)
			if strings.Contains(HTTPRowList.Responsition, "rememberMe") {
				// 这里可以执行相应的处理，比如记录日志、发送通知等
				result = queryAI("请问HTTP请求为：\r\n" + HTTPRowList.Requestion + "\r\nHTTP响应为:\r\n" + response + "\r\n请求体rememberMe是否可base64解码后用shiro默认密钥'kPH+bIxk5D2deZiIxcaaaA=='进行AES解密，判断是否为恶意JAVA反序列化攻击？")
				HTTPRowList.AIanwser = result
				//fmt.Println(result)
				HTTPRowList.Info = "反序列化数据"
			} else if strings.Contains(HTTPRowList.Requestion, "@type") {
				result = "未见敏感内容"
				fastjsonDNSstrings := []string{"java.net.URL", "java.net.Inet4Address", "java.net.Inet6Address"}
				for _, substr := range fastjsonDNSstrings {
					if strings.Contains(HTTPRowList.Requestion, substr) {
						result = queryAI(fmt.Sprintf("请问HTTP请求为：\r\n"+HTTPRowList.Requestion+"\r\nHTTP响应为:\r\n"+response+"\r\n是否在利用%s进行dnslog探测？判断是否为恶意JAVA反序列化攻击？", substr))
						break // 找到一个匹配项后可选择跳出循环，或继续检查以找到所有匹配项
					}
				}
				fastjsonJDBCRowSetImplStrings := []string{"com.sun.rowset.JdbcRowSetImpl", "org.apache.xbean.propertyeditor.JndiConverter", "org.apache.ibatis.datasource.jndi.JndiDataSourceFactory", "br.com.anteros.dbcp.AnterosDBCPConfig", "com.ibatis.sqlmap.engine.transaction.jta.JtaTransactionConfig"}
				for _, substr := range fastjsonJDBCRowSetImplStrings {
					if strings.Contains(HTTPRowList.Requestion, substr) {
						result = queryAI(fmt.Sprintf("请问HTTP请求为：\r\n"+HTTPRowList.Requestion+"\r\nHTTP响应为:\r\n"+response+"\r\n是否在利用%s外联RMI或者LDAP？判断是否为恶意JAVA反序列化攻击？", substr))
						break // 找到一个匹配项后可选择跳出循环，或继续检查以找到所有匹配项
					}
				}
				if strings.Contains(HTTPRowList.Requestion, "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl") {
					result = queryAI(fmt.Sprintf("请问HTTP请求为：\r\n" + HTTPRowList.Requestion + "\r\nHTTP响应为:\r\n" + response + "\r\n是否在利用com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl进行执行恶意bytecodes？把bytecode base64解码判断是否为恶意JAVA反序列化攻击？"))
				}
				HTTPRowList.AIanwser = result
				//fmt.Println(result)
				HTTPRowList.Info = "反序列化数据"
			} else if re.MatchString(HTTPRowList.Requestion) {
				result = queryAI(fmt.Sprintf("请问HTTP请求为：\r\n" + HTTPRowList.Requestion + "\r\nHTTP响应为:\r\n" + response + "\r\n是否在外联？是否为恶意JAVA反序列化攻击？"))
			} else {
				HTTPRowList.Info = "不含反序列化数据"
				HTTPRowList.AIanwser = "不含反序列化数据"
			}
			pkgData = append(pkgData, HTTPRowList.FormateHTTPListInfo())
			HTTPPkgs = append(HTTPPkgs, HTTPRowList)
			//fmt.Println(pkgData)
		}
	}
}

// 处理HTTP请求。
func (h *httpStream) runRequest() {
	buf := bufio.NewReader(&h.r)
	defer tcpreader.DiscardBytesToEOF(buf)

	h.requestBody = bytes.NewBuffer(nil) // 初始化 request body 缓冲区

	for {
		req, err := http.ReadRequest(buf)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return
		} else if err != nil {
			log.Println("Error reading stream", h.net, h.transport, ":", err)
		} else {
			// 读取请求 body 内容并保存到缓冲区
			body, err := ioutil.ReadAll(req.Body)
			if err != nil {
				log.Println("Error reading request body:", err)
				return
			}
			h.requestBody.Write(body)
			requestion := printRequest(req, h)

			HTTPRowList.No = len(pkgData) + 1
			HTTPRowList.Time = time.Now()
			HTTPRowList.Requestion = requestion
			HTTPRowList.Length = len(requestion)
			uri := req.URL.String()
			if len(uri) > 60 {
				uri = uri[:53] + "..."
			}
			HTTPRowList.URI = uri
			HTTPRowList.Source = h.net.String() + ":" + h.transport.String()
			//fmt.Println(HR)
		}
	}
}

// 打印HTTP请求信息。
func printRequest(req *http.Request, h *httpStream) string {
	var builder strings.Builder

	builder.WriteString("\n\r\n\r")
	builder.WriteString(fmt.Sprintf("%s %s\n\r", h.net, h.transport))
	builder.WriteString("\n\r")
	builder.WriteString(fmt.Sprintf("%s %s %s\n\r", req.Method, req.URL.String(), req.Proto))
	for k, v := range req.Header {
		builder.WriteString(fmt.Sprintf("%s: %s\n\r", k, v[0]))
	}
	builder.WriteString("\n\r")

	if h.requestBody.Len() > 0 {
		builder.WriteString("\n\rPOST Payload:\n\r")
		decodedPayload, err := decodeUTF8(h.requestBody.Bytes())
		if err != nil {
			builder.WriteString(fmt.Sprintf("Error decoding request body: %v\n\r", err))
		} else {
			builder.WriteString(decodedPayload)
		}
	}

	return builder.String()
}

// 打印HTTP响应信息。
func printResponse(resp *http.Response, h *httpStream) string {
	var builder strings.Builder

	builder.WriteString("\n\r")
	builder.WriteString(fmt.Sprintf("%s %s\n\r", resp.Proto, resp.Status))
	// 假设printHeader是一个打印头部信息的函数，这里直接转换为字符串构建
	headerStr := printHeaderToString(resp.Header)
	builder.WriteString(headerStr)
	builder.WriteString("\n\r")

	if h.responseBody.Len() > 0 {
		builder.WriteString("\n\rPOST Payload:\n\r")
		decodedPayload, err := decodeUTF8(h.responseBody.Bytes())
		if err != nil {
			builder.WriteString(fmt.Sprintf("Error decoding response body: %v\n\r", err))
		} else {
			builder.WriteString(decodedPayload)
		}
	}

	return builder.String()
}

// 假设这是将header信息转换为字符串的辅助函数
func printHeaderToString(header http.Header) string {
	var builder strings.Builder
	for k, v := range header {
		builder.WriteString(fmt.Sprintf("%s: %s\n\r", k, v[0]))
	}
	return builder.String()
}

// decodeUTF8 尝试解码 UTF-8 编码的字符串
func decodeUTF8(data []byte) (string, error) {
	if utf8.Valid(data) {
		return string(data), nil
	}
	return "", fmt.Errorf("POST数据为ocsp乱码")
}

// 设置 pcap 数据包捕获，组装 TCP 流，并解析 HTTP 请求和响应。
func http_pkg(device_str string) {
	defer util.Run()()
	var handle *pcap.Handle
	var err error

	// 根据命令行参数设置 pcap 数据包捕获
	if *fname != "" {
		log.Printf("Reading from pcap dump %q", *fname)
		handle, err = pcap.OpenOffline(*fname)
	} else {
		log.Printf("Starting capture on interface %q", iface)
		handle, err = pcap.OpenLive(device_str, int32(*snaplen), false, pcap.BlockForever)
	}
	if err != nil {
		log.Fatal(err)
	}

	if err := handle.SetBPFFilter(*filter); err != nil {
		log.Fatal(err)
	}

	// 设置 TCP 流组装
	streamFactory := &httpStreamFactory{}                  // 实例化httpStreamFactory
	streamPool := tcpassembly.NewStreamPool(streamFactory) // 使用streamFactory创建streamPool
	assembler := tcpassembly.NewAssembler(streamPool)      // 使用streamPool创建assembler
	// 当捕获到TCP数据包时，assembler.AssembleWithTimestamp内部会调用streamFactory.New来创建httpStream实例，
	// 用于处理具体的TCP流数据（即HTTP请求或响应）。

	log.Println("reading in packets")
	// 读取数据包并传递给组装器
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()
	ticker := time.Tick(time.Minute)
	for {
		select {
		case packet := <-packets:
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
			// 定期清理超时的连接
			assembler.FlushOlderThan(time.Now().Add(time.Minute * -2))
		}
	}
}

func (p HTTPRow) FormateHTTPListInfo() string {
	res := ""
	// 将包编号转换为字符串并添加到结果中
	res += strconv.Itoa(p.No)
	// 将时间格式化为特定字符串格式，并去掉首尾的引号
	t := p.Time.Format("\"2006-01-02 15:04:05\"")
	res += blankAdd(7-len(res)) + t[1:len(t)-1]
	// 添加来源信息，确保其在指定的宽度内展示
	res += blankAdd(33-len(res)) + p.Source
	// 添加目的地信息，确保其在指定的宽度内展示
	res += blankAdd(70-len(res)) + p.URI
	// 添加协议信息，确保其在指定的宽度内展示
	res += blankAdd(130-len(res)) + strconv.Itoa(int(p.Length))
	// 添加包长度信息，确保其在指定的宽度内展示
	res += blankAdd(137-len(res)) + p.Info
	return res
}

func queryAI(queryContent string) string {

	// 初始化QWEN聊天机器人客户端，使用您的API密钥
	apiKey := your_key
	qwenclient := qwen.NewWithDefaultChat(apiKey)

	qwenclient.QWenModel = "qwen-turbo"

	// 定义一条消息对话的历史记录
	messages := []qwenmodel.Messages{
		{Role: qwenmodel.ChatUser, Content: queryContent},
	}

	// 获取AI对消息的回复
	resp := qwenclient.GetAIReply(messages)

	// 打印收到的回复
	fmt.Printf("收到的回复：%v\n", resp.Output.Text)
	return resp.Output.Text
}

// insertNewlineEveryNChars 在输入字符串每隔n个字符后插入回车换行符。
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
