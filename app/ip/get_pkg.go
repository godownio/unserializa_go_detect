package ip

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/examples/util"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"log"
	"net"
	"strconv"
	"time"
)

var (
	PkgInfos      []gopacket.Packet
	StartTime     time.Time
	Pkgs          []PkgRow
	AllPkgInfos   []gopacket.Packet
	AllPkgs       []PkgRow
	Map_Pkg_Infos map[PkgRow]gopacket.Packet
	HTTPPkgs      []HTTPRow
)

type PkgRow struct {
	No       int
	Time     time.Time
	Source   string
	Dest     string
	Protocol string
	Length   int
	Info     string
}

var (
	downStreamDataSize = 0 // 单位时间内下行的总字节数
	upStreamDataSize   = 0 // 单位时间内上行的总字节数
	deviceName         = flag.String("i", "eth0", "network interface device name")
)
var (
	SourceIp_filter   = ""
	DestIp_filter     = ""
	SourcePort_filter = ""
	DestPort_filter   = ""
)

//设备名：pcap.FindAllDevs()返回的设备的Name
//snaplen：捕获一个数据包的多少个字节，一般来说对任何情况65535是一个好的实践，如果不关注全部内容，只关注数据包头，可以设置成1024
//promisc：设置网卡是否工作在混杂模式，即是否接收目的地址不为本机的包
//timeout：设置抓到包返回的超时。如果设置成30s，那么每30s才会刷新一次数据包；设置成负数，会立刻刷新数据包，即不做等待
//要记得释放掉handle

var (
	device       string = "eth0"
	snapshot_len int32  = 10240
	snapshotLen  int32  = 1024
	promiscuous  bool   = false
	err          error
	timeout      time.Duration = -1 * time.Second
	handle       *pcap.Handle
	packetCount  int = 0
)
var (
	SortBySourceIp   = 0
	SortByDestIp     = 0
	SortBySourcePort = 0
	SortByDestPort   = 0
	SortByLength     = 0
)

const (
	//0默认无 1递增 2递减
	INCRESE = 1
	DECRESE = 2
)

var IsGetPkg bool = false

// 混杂模式
var Promiscuous bool = false
var (
	Sort_tpyes = 0
)
var Interupt bool = false

// GetPkg 是一个用于捕获和分析网络包的函数。
// 参数:
// - ctx: 上下文，用于控制函数的生命周期。
// - device_str: 指定要捕获数据的设备名称字符串。
// 该函数没有返回值。
func GetPkg(ctx context.Context, device_str string) {
	InitData() // 初始化数据

	// 设置捕获参数
	No := 1

	// 尝试打开指定设备以开始捕获数据
	device = device_str
	handle, err := pcap.OpenLive(device_str, snapshot_len, Promiscuous, timeout)
	if err != nil {
		log.Fatal(err) // 如果打开设备失败，则记录错误并退出程序
	}
	defer handle.Close() // 确保在函数退出前关闭设备句柄

	// 创建数据包源
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// 获取所有网络设备信息，并查找与指定设备名称匹配的设备
	devices, err := pcap.FindAllDevs()
	var device pcap.Interface
	for _, d := range devices {
		if d.Name == device_str {
			device = d
		}
	}

	// 获取指定设备的MAC地址
	macAddr, err := findMacAddrByIp(findDeviceIpv4(device))
	if err != nil {
		panic(err) // 如果获取MAC地址失败，则panic
	}

	// 启动一个goroutine来监控捕获过程
	ctx1, cancel1 := context.WithCancel(context.Background())
	go monitor(ctx1)
	defer cancel1()

	// 开始捕获并分析数据包
	for packet := range packetSource.Packets() {
		if Interupt == false {
			p := anlysePacket(packet)                 // 分析数据包
			p.No = No                                 // 设置数据包编号
			AllPkgs = append(AllPkgs, p)              // 将分析结果添加到全局包列表
			AllPkgInfos = append(AllPkgInfos, packet) // 将原始数据包添加到全局包信息列表
			Map_Pkg_Infos[p] = packet                 // 将分析结果与原始数据包映射(key-value)
			if (SourceIp_filter == "" || p.Source == SourceIp_filter) &&
				(DestIp_filter == "" || p.Dest == DestIp_filter) &&
				(SourcePort_filter == "" || get_source_port(p.Info) == SourcePort_filter) &&
				(DestPort_filter == "" || get_dest_port(p.Info) == DestPort_filter) {
				// 根据Sort_tpyes的值决定包信息的插入方式。
				// 如果Sort_tpyes不为0，则按照特定规则插入信息；
				// 也就是根据源目ip大小排序插入
				if Sort_tpyes != 0 {
					// 根据Sort_tpyes获取插入索引，然后分别插入包信息到Pkgs、PkgInfos和PkgStringList中
					index := GetIndexInsert(PkgStringList, p.FormatePkgListInfo(), Sort_tpyes)
					InsertPkgRow(&Pkgs, index, p)
					InsertPkgInfo(&PkgInfos, index, packet)
					InsertStr(&PkgStringList, index, p.FormatePkgListInfo())
				} else {
					// 当Sort_tpyes为0时，直接追加包信息到Pkgs、PkgInfos和PkgStringList末尾
					Pkgs = append(Pkgs, p)
					PkgInfos = append(PkgInfos, packet)
					PkgStringList = append(PkgStringList, p.FormatePkgListInfo())
				}

				if SortBySourceIp == INCRESE {
					ReLoadPkgList(PkgSortBySourceIp(Pkgs))
				} else if SortBySourceIp == DECRESE {
					ReLoadPkgList(PkgSortBySourceIpReverse(Pkgs))
				} else if SortByDestIp == INCRESE {
					ReLoadPkgList(PkgSortByDestIp(Pkgs))
				} else if SortByDestIp == DECRESE {
					ReLoadPkgList(PkgSortByDestIpReverse(Pkgs))
				} else if SortByLength == INCRESE {
					ReLoadPkgList(PkgSortByLength(Pkgs))
				} else if SortByLength == DECRESE {
					ReLoadPkgList(PkgSortByLengthReverse(Pkgs))
				} else if SortBySourcePort == INCRESE {
					ReLoadPkgList(PkgSortBySourcePort(Pkgs))
				} else if SortBySourcePort == DECRESE {
					ReLoadPkgList(PkgSortBySourcePortReverse(Pkgs))
				} else if SortByDestPort == INCRESE {
					ReLoadPkgList(PkgSortByDestPort(Pkgs))
				} else if SortByDestPort == DECRESE {
					ReLoadPkgList(PkgSortByDestPortReverse(Pkgs))
				}
			}
			//统计流量
			ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
			if ethernetLayer != nil {
				ethernet := ethernetLayer.(*layers.Ethernet)
				// 如果封包的目的MAC是本机则表示是下行的数据包，否则为上行
				if ethernet.DstMAC.String() == macAddr {
					downStreamDataSize += len(packet.Data()) // 统计下行封包总大小
				} else {
					upStreamDataSize += len(packet.Data()) // 统计上行封包总大小
				}
			}
			//fmt.Println(packet.Layers()[len(packet.Layers())-1].LayerContents())
		}
		No++
		select {
		case <-ctx.Done():
			return
		default:

		}
	}
}

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

func setFlliter(device string, p string, port int) {
	// Open device
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()
	// Set filter
	var filter string = p + " and port " + strconv.Itoa(port)
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Only capturing " + p + " port " + strconv.Itoa(port) + " packets.")

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// Do something with a packet here.
		fmt.Println(packet)
	}
}

// anlysePacket 分析传入的gopacket.Packet数据包，并返回一个PkgRow结构体实例，包含数据包的详细信息。
// - p: gopacket.Packet 类型，表示待分析的数据包。
// 返回值: - PkgRow: 包含数据包的时间、长度、源地址、目的地址、协议类型和额外信息的结构体。
func anlysePacket(p gopacket.Packet) PkgRow {
	// 初始化空的Endpoint和Flow
	var nilEndpoint gopacket.Endpoint = gopacket.Endpoint{}
	var nilFlow gopacket.Flow = gopacket.Flow{}
	// 初始化PkgRow实例
	pkgrow := PkgRow{Time: p.Metadata().Timestamp,
		Length: p.Metadata().Length,
	}
	// 分析网络层信息
	if p.NetworkLayer() != nil { // 判断是否存在网络层
		// 获取源地址和目的地址
		if p.NetworkLayer().NetworkFlow().Src() != nilEndpoint {
			pkgrow.Source = p.NetworkLayer().NetworkFlow().Src().String()
		}
		if p.NetworkLayer().NetworkFlow().Dst() != nilEndpoint {
			pkgrow.Dest = p.NetworkLayer().NetworkFlow().Dst().String()
		}
		// 获取协议类型
		if p.NetworkLayer().NetworkFlow() != nilFlow {
			pkgrow.Protocol = p.NetworkLayer().NetworkFlow().EndpointType().String()
		}
	}
	// 分析传输层信息
	if p.TransportLayer() != nil { // 判断是否存在传输层
		// 获取传输层的协议类型和信息
		if p.TransportLayer().TransportFlow() != nilFlow {
			pkgrow.Protocol = p.TransportLayer().TransportFlow().EndpointType().String()
			pkgrow.Info = p.TransportLayer().TransportFlow().String()
		}
		// 如果存在应用层，进一步分析协议类型
		if p.ApplicationLayer() != nil {
			switch p.ApplicationLayer().LayerType() {
			case layers.LayerTypeTLS:
				pkgrow.Protocol = "TLS"
			case layers.LayerTypeDNS:
				pkgrow.Protocol = "DNS"
			}
		}
	}
	return pkgrow
}

// PkgRow 是一个存储包信息的结构体类型
// FormatePkgListInfo 格式化包列表信息
// 该函数不接受参数，返回一个格式化后的字符串，该字符串按照固定的宽度和格式展示了包的各个属性，
// 包括编号、时间、来源、目的地、协议、长度和信息。
func (p PkgRow) FormatePkgListInfo() string {
	res := ""
	// 将包编号转换为字符串并添加到结果中
	res += strconv.Itoa(p.No)
	// 将时间格式化为特定字符串格式，并去掉首尾的引号
	t := p.Time.Format("\"2006-01-02T15:04:05\"")
	res += blankAdd(15-len(res)) + t[1:len(t)-1]
	// 添加来源信息，确保其在指定的宽度内展示
	res += blankAdd(45-len(res)) + p.Source
	// 添加目的地信息，确保其在指定的宽度内展示
	res += blankAdd(70-len(res)) + p.Dest
	// 添加协议信息，确保其在指定的宽度内展示
	res += blankAdd(98-len(res)) + p.Protocol
	// 添加包长度信息，确保其在指定的宽度内展示
	res += blankAdd(115-len(res)) + strconv.Itoa(p.Length)
	// 添加包信息，确保其在指定的宽度内展示
	res += blankAdd(129-len(res)) + p.Info
	return res
}

// blankAdd 生成一个包含指定数量空格的字符串
// 参数 n 指定生成空格的数量。
// 返回一个包含 n 个空格的字符串。
func blankAdd(n int) string {
	res := ""
	// 循环添加 n 个空格到结果字符串中
	for n > 0 {
		n--
		res += " "
	}
	return res
}

// 获取网卡的IPv4地址
func findDeviceIpv4(device pcap.Interface) string {
	for _, addr := range device.Addresses {
		if ipv4 := addr.IP.To4(); ipv4 != nil {
			return ipv4.String()
		}
	}
	panic("device has no IPv4")
}

// 根据网卡的IPv4地址获取MAC地址
// 有此方法是因为gopacket内部未封装获取MAC地址的方法，所以这里通过找到IPv4地址相同的网卡来寻找MAC地址
func findMacAddrByIp(ip string) (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		panic(interfaces)
	}

	for _, i := range interfaces {
		addrs, err := i.Addrs()
		if err != nil {
			panic(err)
		}

		for _, addr := range addrs {
			if a, ok := addr.(*net.IPNet); ok {
				if ip == a.IP.String() {
					return i.HardwareAddr.String(), nil
				}
			}
		}
	}
	return "", errors.New(fmt.Sprintf("no device has given ip: %s", ip))
}

// 每一秒计算一次该秒内的数据包大小平均值，并将下载、上传总量置零
func monitor(ctx context.Context) {
	for {
		FlowsStr.Set(fmt.Sprintf("\rDown:%.2fkb/s \t Up:%.2fkb/s                                                                                                                             ", float32(downStreamDataSize)/1024/1, float32(upStreamDataSize)/1024/1))
		downStreamDataSize = 0
		upStreamDataSize = 0
		time.Sleep(1 * time.Second)
		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}
func InitData() {
	fmt.Println("初始化数据成功")
	Map_Pkg_Infos = make(map[PkgRow]gopacket.Packet)
	AllPkgs = []PkgRow{}
	AllPkgInfos = []gopacket.Packet{}
	Pkgs = []PkgRow{}
	PkgInfos = []gopacket.Packet{}
	PkgStringList = []string{}
}
