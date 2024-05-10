package ip

import (
	"bytes"
	"context"
	"embed"
	fyne2 "fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"image"
)

//go:embed UI1.jpg
//go:embed 匕首武器战争.png
var resources embed.FS

var DeviceName string
var A fyne2.App
var IP string
var Icon fyne2.Resource
var Ctx context.Context
var Cancel context.CancelFunc
var backgroundContainer *fyne2.Container

func Run() {
	Ctx, Cancel = context.WithCancel(context.Background())
	A := app.New()
	w := A.NewWindow("反序列化检测及全流量")
	imgBytes, err := resources.ReadFile("UI1.jpg")
	// 将图片数据转换为image.Image
	imgPath, _, err := image.Decode(bytes.NewReader(imgBytes))
	img := canvas.NewImageFromImage(imgPath)
	img.FillMode = canvas.ImageFillStretch

	IconBytes, err := resources.ReadFile("匕首武器战争.png")
	// 解码图片数据
	//IconPath, _, err := image.Decode(bytes.NewReader(IconBytes))
	Icon := fyne2.NewStaticResource("icon", IconBytes)
	if err != nil {
		fyne2.LogError("icon加载失败", err)
	}
	w.SetIcon(Icon)
	w.SetMaster()
	LoadMenus(w, A)         //选项菜单
	ifaces := Get_if_list() //获取设备
	Layers := LoadLayers()
	PkgInfo := LoadPkgInfo()
	Monitor := LoadMonitor()
	PkgList := LoadPkgList()
	HTTPList := LoadHTTPList()
	HTTPMonitor := LoadHTTPMonitor()
	HTTPPkgInfo := LoadHTTPPkgInfo()
	HTTPPkgInfo.Move(fyne2.NewPos(0, 280))
	HTTPMonitor.Move(fyne2.NewPos(900, 560))
	NewContainer := container.NewWithoutLayout(HTTPList, HTTPPkgInfo, HTTPMonitor)
	NewbackgroundContainer = container.NewMax(
		img,
		NewContainer,
	)
	PkgListContainer := container.NewWithoutLayout(PkgList)
	Layers.Move(fyne2.NewPos(0, 280))
	PkgInfo.Move(fyne2.NewPos(0, 520))
	Monitor.Move(fyne2.NewPos(0, 760))
	AllContainer := container.NewWithoutLayout(PkgListContainer, Layers, PkgInfo, Monitor)
	backgroundContainer = container.NewMax(
		img,
		AllContainer,
	)
	w.SetContent(backgroundContainer)
	w.Resize(fyne2.NewSize(1400, 630))
	DeviceName = ifaces[0].NPFName
	w.Resize(fyne2.NewSize(1400, 630))
	w.Show()
	A.Run()
}
