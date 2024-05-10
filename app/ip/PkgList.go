package ip

import (
	"fmt"
	fyne2 "fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
	//"time"
)

var PkgStringList []string
var PkgList *widget.List

// LoadPkgList 创建并返回一个包含包信息列表的容器对象。
// 该函数不接受参数，返回一个 *fyne2.Container 对象，该对象用于在GUI中展示包信息列表。
func LoadPkgList() *fyne2.Container {
	// 初始化包信息文本，用于构建列表的头部。
	pkgText := []string{
		"No.     ", "Time                          ", "Source              ", "Dst                      ",
		"Protocol   ", "Length     ", "Info                                   ",
	}

	// 创建一个水平盒子容器，用于放置头部文本按钮。
	pkgTextContainer := container.NewHBox()
	for _, v := range pkgText {
		// 为每个头部文本创建一个按钮，并添加到盒子容器中，虽然按钮点击事件未实现。
		pkgTextContainer.Add(widget.NewButton(v, func() {

		}))
	}

	// 创建包信息列表，包括列表的项目数量、项目展示样式和项目更新逻辑。
	PkgList = widget.NewList(
		func() int {
			// 返回包信息列表的项目数量。
			return len(PkgStringList)
		},
		func() fyne2.CanvasObject {
			// 返回一个用于列表项模板的标签对象。
			return widget.NewLabel("template")
		},
		func(i widget.ListItemID, o fyne2.CanvasObject) {
			// 设置列表项的文本内容。
			//fmt.Println(PkgStringList)
			o.(*widget.Label).SetText(PkgStringList[i])
		})

	// 设置包信息列表的选中事件处理逻辑。
	PkgList.OnSelected = func(id widget.ListItemID) {
		// 当选中某个包信息时，打印相关数据长度，并更新UI展示该包的详细信息。
		packet := Map_Pkg_Infos[Pkgs[id]]
		fmt.Println(len(Map_Pkg_Infos), len(Pkgs), len(AllPkgInfos))
		NewLayersData(id+1, packet)
		LayersWidget.Refresh()
		NewPkgInfoData(packet)
	}

	// 创建一个分隔符对象，用于改善UI布局。
	s := widget.NewSeparator()
	// 将头部文本容器、分隔符和包信息列表组合在一个带有边框的容器中。
	PkgListContainer := container.NewBorder(pkgTextContainer, nil, nil, s, PkgList)
	// 设置容器的初始大小。
	PkgListContainer.Resize(fyne2.NewSize(1400, 280))

	// 返回构建好的包信息列表容器。
	return PkgListContainer
}

func ReLoadPkgList(Pkgs []PkgRow) {
	pkgStringList := []string{}
	//
	for _, v := range Pkgs {
		pkgStringList = append(pkgStringList, v.FormatePkgListInfo())
	}
	PkgStringList = pkgStringList
}
func AddList(strings []string, string2 string) {
	strings = append(strings, string2)
}
