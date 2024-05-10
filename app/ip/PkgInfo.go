package ip

import (
	"fyne.io/fyne/v2"
	fyne2 "fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
	"github.com/google/gopacket"
	//"github.com/google/gopacket"
)

var (
	PkgInfoWidget fyne2.Widget
	PkgCharWidget fyne2.Widget
	PkgMetaData   [][]string
	PkgCharData   [][]string
)

// LoadPkgInfo 加载并显示包信息和包字符信息的函数。
// 返回 *fyne2.Container: 一个包含包信息和包字符信息的容器对象，可以被FYNE应用程序进一步使用和显示。
func LoadPkgInfo() *fyne2.Container {
	// 创建一个分隔符 widget
	speparator := widget.NewSeparator()

	// 初始化包信息表格
	PkgInfoWidget = widget.NewTable(
		func() (int, int) { // 表格的行和列数
			if len(PkgMetaData) != 0 {
				return len(PkgMetaData), len(PkgMetaData[0])
			}
			return 0, 0
		},
		func() fyne.CanvasObject { // 创建每个单元格的默认内容
			return widget.NewLabel("00")
		},
		func(tableCellID widget.TableCellID, object fyne.CanvasObject) { // 设置单元格文本
			l := object.(*widget.Label)
			l.SetText(PkgMetaData[tableCellID.Row][tableCellID.Col])
		},
	)

	// 初始化包字符信息表格
	PkgCharWidget = widget.NewTable(
		func() (int, int) { // 表格的行和列数
			if len(PkgCharData) != 0 {
				return len(PkgCharData), len(PkgCharData[0])
			}
			return 0, 0
		},
		func() fyne.CanvasObject { // 创建每个单元格的默认内容
			return widget.NewLabel("00")
		},
		func(tableCellID widget.TableCellID, object fyne.CanvasObject) { // 设置单元格文本
			l := object.(*widget.Label)
			l.SetText(PkgCharData[tableCellID.Row][tableCellID.Col])
		},
	)

	// 配置两个表格之间的交互，当一个表格的单元格被选中时，另一个表格选中对应的单元格
	PkgInfoWidget.(*widget.Table).OnSelected = func(id widget.TableCellID) {
		PkgCharWidget.(*widget.Table).Select(id)
	}
	PkgCharWidget.(*widget.Table).OnSelected = func(id widget.TableCellID) {
		PkgInfoWidget.(*widget.Table).Select(id)
	}

	// 创建包含两个表格的容器，并设置它们的大小和位置
	InfoContainer := container.NewBorder(nil, nil, nil, nil, PkgInfoWidget)          // 包信息容器
	CharContainer := container.NewBorder(nil, nil, nil, nil, PkgCharWidget)          // 包字符信息容器
	InfoContainer.Resize(fyne2.NewSize(560, 240))                                    // 设置包信息容器大小
	CharContainer.Resize(fyne2.NewSize(560, 240))                                    // 设置包字符信息容器大小
	InfoContainer.Move(fyne2.NewPos(0, 0))                                           // 设置包信息容器位置
	CharContainer.Move(fyne2.NewPos(600, 0))                                         // 设置包字符信息容器位置
	InfoAndCharContainer := container.NewWithoutLayout(InfoContainer, CharContainer) // 将两个容器组合在一起

	// 创建并配置最终的包信息容器，包含分隔符和组合容器
	PkgInfoContainer := container.NewBorder(nil, speparator, nil, nil, InfoAndCharContainer) // 最终容器
	PkgInfoContainer.Resize(fyne2.NewSize(1400, 240))                                        // 设置最终容器的大小

	return PkgInfoContainer // 返回最终容器
}
func LoadHTTPPkgInfo() *fyne2.Container {
	// 创建一个分隔符 widget
	speparator := widget.NewSeparator()
	// 初始化包信息表格
	HTTPReqWidget = widget.NewEntry()
	// 初始化包字符信息表格
	HTTPRespWidget = widget.NewEntry()
	HTTPAIanwserWidget = widget.NewEntry()

	// 创建包含两个表格的容器，并设置它们的大小和位置
	ReqContainer := container.NewBorder(nil, nil, nil, nil, HTTPReqWidget) // 包信息容器
	RespContainer := container.NewBorder(nil, nil, nil, nil, HTTPRespWidget)
	AIanwserContainer := container.NewBorder(nil, nil, nil, nil, HTTPAIanwserWidget) // 包字符信息容器
	ReqContainer.Resize(fyne2.NewSize(400, 240))                                     // 设置包信息容器大小
	RespContainer.Resize(fyne2.NewSize(400, 240))
	AIanwserContainer.Resize(fyne2.NewSize(450, 240)) // 设置包字符信息容器大小
	ReqContainer.Move(fyne2.NewPos(0, 0))             // 设置包信息容器位置
	RespContainer.Move(fyne2.NewPos(450, 0))
	AIanwserContainer.Move(fyne2.NewPos(900, 0))                                                       // 设置包字符信息容器位置
	InfoAndCharContainer := container.NewWithoutLayout(ReqContainer, RespContainer, AIanwserContainer) // 将两个容器组合在一起

	// 创建并配置最终的包信息容器，包含分隔符和组合容器
	PkgInfoContainer := container.NewBorder(nil, speparator, nil, nil, InfoAndCharContainer) // 最终容器
	PkgInfoContainer.Resize(fyne2.NewSize(1400, 240))                                        // 设置最终容器的大小

	return PkgInfoContainer // 返回最终容器
}

func NewPkgInfoData(packet gopacket.Packet) {
	PkgMetaData = PkgBytes2StringSlice(packet.Data())
	PkgCharData = PkgBytes2AsciiSlice(packet.Data())
	PkgInfoWidget.Refresh()
	PkgCharWidget.Refresh()
}
func PkgBytes2String(PkgBytes []byte) string {
	res := ""
	for _, v := range PkgBytes {
		res += byte2Hex(v)
	}
	return res
}
func PkgBytes2AsciiSlice(PkgBytes []byte) [][]string {
	res := [][]string{}
	for i := 0; i < len(PkgBytes); {
		temp := []string{}
		c := 0
		for i < len(PkgBytes) && c != 16 {
			temp = append(temp, Byte2AscllString(PkgBytes[i]))
			if i%16 == 7 {
				temp = append(temp, " ")
			}
			i++
			c++
		}
		if c == 16 {
			res = append(res, temp)
			c = 0
		} else if i == len(PkgBytes) { //如果最后不足一行则补齐空string
			for len(temp) < 17 {
				temp = append(temp, " ")
			}
			res = append(res, temp)
		}
	}
	return res
}

func Byte2AscllString(b byte) string {
	bint := int(b)
	if bint >= 33 && bint <= 126 {
		return string(b)
	}
	return "."

}
func PkgBytes2StringSlice(PkgBytes []byte) [][]string {
	res := [][]string{}
	for i := 0; i < len(PkgBytes); {
		temp := []string{}
		c := 0
		for i < len(PkgBytes) && c != 16 {
			temp = append(temp, byte2Hex(PkgBytes[i]))
			if i%16 == 7 {
				temp = append(temp, " ")
			}
			i++
			c++
		}
		if c == 16 {
			res = append(res, temp)
			c = 0
		} else if i == len(PkgBytes) { //如果最后不足一行则补齐空string
			for len(temp) < 17 {
				temp = append(temp, " ")
			}
			res = append(res, temp)
		}
	}
	return res
}
func byte2Hex(b byte) string {
	care := []string{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"}
	bb := int(b)
	res := ""
	if b == 0 {
		return "00"
	}
	if b < 16 {
		return "0" + care[bb%16]
	}
	for bb > 0 {
		res = care[bb%16] + res
		bb /= 16
	}
	return res
}
