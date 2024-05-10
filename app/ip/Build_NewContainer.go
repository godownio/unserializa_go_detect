package ip

import (
	fyne2 "fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
	"time"
)

var pkgData []string
var NewbackgroundContainer *fyne2.Container
var HTTPReqWidget = widget.NewEntry()
var HTTPRespWidget = widget.NewEntry()
var HTTPAIanwserWidget = widget.NewEntry()
var NowHTTPRow HTTPRow

type HTTPRow struct {
	No           int
	Time         time.Time
	Source       string
	URI          string
	Length       int
	Requestion   string
	Responsition string
	Info         string
	AIanwser     string
}

// LoadPkgList 创建并返回一个包含包信息列表的容器对象。
// 该函数不接受参数，返回一个 *fyne2.Container 对象，该对象用于在GUI中展示包信息列表。
func LoadHTTPList() *fyne2.Container {
	// 初始化包信息文本，用于构建列表的头部。
	pkgText := []string{
		"No. ", "Time                  ", "Source                           ", "URI                                                    ",
		"Length ", "Info                                 ",
	}

	// 创建一个水平盒子容器，用于放置头部文本按钮。
	HTTPTextContainer := container.NewHBox()
	for _, v := range pkgText {
		// 为每个头部文本创建一个按钮，并添加到盒子容器中。
		btn := widget.NewButton(v, func() {
			// 按钮点击事件处理逻辑
			// 这里暂时不需要做任何事情，因为头部文本按钮不需要点击事件
		})
		HTTPTextContainer.Add(btn)
	}

	// 创建一个分隔符对象，用于改善UI布局。
	s := widget.NewSeparator()

	// 创建包信息列表组件，用于展示包信息。
	PkgList = widget.NewList(
		// 获取列表项总数
		func() int {
			return len(pkgData)
		},
		// 创建列表项内容
		func() fyne2.CanvasObject {
			return widget.NewLabel("") // 初始为空
		},
		// 更新列表项内容
		func(i widget.ListItemID, o fyne2.CanvasObject) {
			//fmt.Println(pkgData[i])
			o.(*widget.Label).SetText(pkgData[i]) // 设置列表项文本
		},
	)

	// 设置列表点击事件处理逻辑
	PkgList.OnSelected = func(id widget.ListItemID) {
		NowHTTPRow = HTTPPkgs[id]
		//fmt.Println(NowHTTPRow)
		HTTPReqWidget.SetText(NowHTTPRow.Requestion)
		HTTPRespWidget.SetText(NowHTTPRow.Responsition)
		HTTPAIanwserWidget.SetText(NowHTTPRow.AIanwser)
	}

	// 将头部文本容器、分隔符和包信息列表组合在一个带有边框的容器中。
	PkgListContainer := container.NewBorder(HTTPTextContainer, nil, nil, s, PkgList)
	// 设置容器的初始大小。
	PkgListContainer.Resize(fyne2.NewSize(1400, 280))

	// 返回构建好的包信息列表容器。
	return PkgListContainer
}
