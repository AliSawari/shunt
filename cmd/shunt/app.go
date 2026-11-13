package main

import (
	"fmt"
	"image"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
	"golang.org/x/sys/windows"

	"shunt/internal/brand"
	"shunt/internal/core"
	"shunt/internal/profile"
	"shunt/internal/tun"
)

// attachConsole lets the CLI sub-commands print to the terminal they were
// started from even though shunt.exe is a GUI-subsystem program.
func attachConsole() {
	windows.NewLazySystemDLL("kernel32.dll").NewProc("AttachConsole").Call(^uintptr(0))
	if f, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0); err == nil {
		os.Stdout, os.Stderr = f, f
		log.SetOutput(f)
	}
}

type app struct {
	mw           *walk.MainWindow
	tb           *walk.ToolBar
	prof         *profile.Profile
	path         string
	kr           *profile.Keyring
	eng          *core.Engine
	busy         bool
	quitting     bool
	settings     uiSettings
	ni           *walk.NotifyIcon
	trayStart    *walk.Action
	trayCloseAct *walk.Action
	startAct     *walk.Action
	startBtn     *walk.PushButton
	stateLbl     *walk.Label
	stateSub     *walk.Label
	connTV       *walk.TableView
	conns        *connModel
	logTE        *walk.TextEdit
	sbi          *walk.StatusBarItem
	icons        map[string]*walk.Icon

	logMu  sync.Mutex
	logBuf strings.Builder
}

func (a *app) Write(p []byte) (int, error) {
	a.logMu.Lock()
	a.logBuf.Write(p)
	a.logMu.Unlock()
	return len(p), nil
}

// safe wraps a UI handler so an unexpected error is logged and reported
// instead of closing the program.
func (a *app) safe(f func()) func() {
	return func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("internal error: %v\n%s", r, debug.Stack())
				walk.MsgBox(a.mw, "Shunt", fmt.Sprintf("An internal error occurred and was written to the log:\n\n%v", r), walk.MsgBoxIconError)
			}
		}()
		f()
	}
}

// ---- connections table -----------------------------------------------------

type connModel struct {
	walk.TableModelBase
	rows []*core.ConnInfo
}

func (m *connModel) RowCount() int { return len(m.rows) }
func (m *connModel) Value(row, col int) interface{} {
	if row >= len(m.rows) {
		return ""
	}
	c := m.rows[row]
	switch col {
	case 0:
		return fmt.Sprintf("%s (%d)", c.App, c.PID)
	case 1:
		return c.Target
	case 2:
		if c.Closed.Load() {
			return "Closed"
		}
		d := time.Since(c.Start)
		return fmt.Sprintf("%02d:%02d", int(d.Minutes()), int(d.Seconds())%60)
	case 3:
		return c.Rule + " : " + c.Via
	case 4:
		return size(c.Sent.Load())
	case 5:
		return size(c.Recv.Load())
	}
	return ""
}

// usesProxy reports whether any enabled rule routes through a proxy or chain.
func usesProxy(p *profile.Profile) bool {
	for _, r := range p.Rules {
		if r.Enabled && (r.Action.Type == profile.ActProxy || r.Action.Type == profile.ActChain) {
			return true
		}
	}
	return false
}

func openURL(u string) {
	verb, _ := windows.UTF16PtrFromString("open")
	file, _ := windows.UTF16PtrFromString(u)
	windows.ShellExecute(0, verb, file, nil, nil, windows.SW_SHOWNORMAL)
}

// setupLogging sends the log to the window, to shunt.log and fatal crashes
// to crash.log. Problems with the files are reported in the window.
func (a *app) setupLogging() {
	dir := configDir()
	os.MkdirAll(dir, 0o755)
	if f, err := os.OpenFile(filepath.Join(dir, "crash.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644); err == nil {
		debug.SetCrashOutput(f, debug.CrashOptions{})
	}
	var out io.Writer = a
	path := filepath.Join(dir, "shunt.log")
	lf, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err == nil {
		_, err = fmt.Fprintf(lf, "---- %s Shunt %s started (pid %d, administrator: %v)\n", time.Now().Format("2006-01-02 15:04:05"), version, os.Getpid(), tun.Elevated())
	}
	if err == nil {
		out = io.MultiWriter(a, lf)
	}
	log.SetOutput(out)
	if err != nil {
		log.Printf("Log file %s cannot be written: %v", path, err)
	} else {
		log.Printf("Log file: %s", path)
	}
}

func (a *app) icon(name string, img func(int) *image.NRGBA, px int) *walk.Icon {
	key := fmt.Sprint(name, px)
	if ic, ok := a.icons[key]; ok {
		return ic
	}
	ic, err := walk.NewIconFromImageForDPI(img(px), 96)
	if err != nil {
		return nil
	}
	a.icons[key] = ic
	return ic
}

// singleInstance makes sure only one Shunt window runs: two instances would
// fight over the same tunnel adapter. A second launch brings the first window
// to the front. The elevated relaunch (-start) waits for the old one to exit.
// instanceMutex names the single-instance lock. Test builds that must run
// next to a normal instance override it with -ldflags "-X main.instanceMutex=...".
var instanceMutex = `Local\Shunt.SingleInstance`

func singleInstance(wait bool) bool {
	name, _ := windows.UTF16PtrFromString(instanceMutex)
	h, err := windows.CreateMutex(nil, false, name)
	if h == 0 {
		focusExisting()
		return false
	}
	timeout := uint32(0)
	if wait {
		timeout = 10000
	}
	ev, _ := windows.WaitForSingleObject(h, timeout)
	if ev == windows.WAIT_OBJECT_0 || ev == uint32(windows.WAIT_ABANDONED) {
		return true // owned until the process exits
	}
	_ = err
	focusExisting()
	return false
}

func focusExisting() {
	u := windows.NewLazySystemDLL("user32.dll")
	title, _ := windows.UTF16PtrFromString("Shunt")
	hwnd, _, _ := u.NewProc("FindWindowW").Call(0, uintptr(unsafe.Pointer(title)))
	if hwnd != 0 {
		u.NewProc("ShowWindow").Call(hwnd, 9) // SW_RESTORE
		u.NewProc("SetForegroundWindow").Call(hwnd)
	}
}

func gui() {
	autoStart := len(os.Args) > 1 && os.Args[1] == "-start"
	if !singleInstance(autoStart) {
		return
	}
	a := &app{path: defaultProfile(), kr: &profile.Keyring{Master: os.Getenv("SHUNT_MASTER_PASSWORD")}, conns: &connModel{}, icons: map[string]*walk.Icon{}}
	a.setupLogging()
	a.settings = loadSettings()
	if p, err := profile.Load(a.path, a.kr); err == nil {
		a.prof = p
	} else {
		if !os.IsNotExist(err) {
			log.Printf("Cannot read profile %s: %v. Using a new profile.", a.path, err)
		}
		a.prof = profile.Default()
	}

	var startAct, proxiesAct, rulesAct, dnsAct, advAct, checkAct *walk.Action
	err := MainWindow{
		AssignTo: &a.mw,
		Title:    "Shunt",
		MinSize:  Size{Width: 760, Height: 460},
		Size:     Size{Width: 1000, Height: 660},
		Layout:   VBox{MarginsZero: true, SpacingZero: true},
		MenuItems: []MenuItem{
			Menu{Text: "&File", Items: []MenuItem{
				Action{Text: "&New Profile", OnTriggered: a.safe(func() { a.setProfile(profile.Default()) })},
				Action{Text: "&Import Profile...", OnTriggered: a.safe(a.importProfile)},
				Action{Text: "&Export Profile...", OnTriggered: a.safe(a.exportProfile)},
				Separator{},
				Action{Text: "Open &Log Folder", OnTriggered: func() { openURL(configDir()) }},
				Separator{},
				Action{Text: "E&xit", OnTriggered: a.quit},
			}},
			Menu{Text: "&Profile", Items: []MenuItem{
				Action{Text: "&Proxy Servers...", OnTriggered: a.safe(a.proxiesDialog)},
				Action{Text: "Proxification &Rules...", OnTriggered: a.safe(a.rulesDialog)},
				Action{Text: "&Name Resolution...", OnTriggered: a.safe(a.dnsDialog)},
				Action{Text: "&Advanced...", OnTriggered: a.safe(a.advancedDialog)},
			}},
			Menu{Text: "&View", Items: []MenuItem{
				Action{Text: "&Disconnect Selected", OnTriggered: a.safe(a.disconnect)},
				Action{Text: "&Clear Log", OnTriggered: func() { a.logTE.SetText("") }},
				Separator{},
				Action{AssignTo: &a.trayCloseAct, Text: "Close Button &Minimizes to Tray", Checkable: true, Checked: a.settings.CloseAction == closeTray, OnTriggered: func() {
					a.settings.CloseAction = closeAsk
					if a.trayCloseAct.Checked() {
						a.settings.CloseAction = closeTray
					}
					a.saveSettings()
				}},
			}},
			Menu{Text: "&Help", Items: []MenuItem{
				Action{Text: "&GitHub Page", OnTriggered: func() { openURL(brand.RepoURL) }},
				Action{Text: "&About Shunt...", OnTriggered: a.safe(a.about)},
			}},
		},
		ToolBar: ToolBar{AssignTo: &a.tb, ButtonStyle: ToolBarButtonImageBeforeText, Items: []MenuItem{
			Action{AssignTo: &startAct, Text: "Start", OnTriggered: a.safe(a.toggle)},
			Separator{},
			Action{AssignTo: &proxiesAct, Text: "Proxy Servers", OnTriggered: a.safe(a.proxiesDialog)},
			Action{AssignTo: &rulesAct, Text: "Proxification Rules", OnTriggered: a.safe(a.rulesDialog)},
			Action{AssignTo: &dnsAct, Text: "Name Resolution", OnTriggered: a.safe(a.dnsDialog)},
			Action{AssignTo: &advAct, Text: "Advanced", OnTriggered: a.safe(a.advancedDialog)},
			Separator{},
			Action{AssignTo: &checkAct, Text: "Proxy Checker", OnTriggered: a.safe(a.checkDefaultProxy)},
		}},
		Children: []Widget{
			Composite{
				Layout: HBox{Margins: Margins{Left: 12, Top: 10, Right: 12, Bottom: 10}, Spacing: 14},
				Children: []Widget{
					PushButton{AssignTo: &a.startBtn, Text: "  Start", MinSize: Size{Width: 160, Height: 46}, MaxSize: Size{Width: 160, Height: 46},
						Font: Font{Family: "Segoe UI", PointSize: 12, Bold: true}, OnClicked: a.safe(a.toggle)},
					Composite{Layout: VBox{MarginsZero: true, SpacingZero: true}, Children: []Widget{
						Label{AssignTo: &a.stateLbl, Text: "Stopped", Font: Font{Family: "Segoe UI", PointSize: 13, Bold: true}},
						Label{AssignTo: &a.stateSub, Text: "", Font: Font{Family: "Segoe UI", PointSize: 9}},
					}},
					HSpacer{},
				},
			},
			VSplitter{Children: []Widget{
				TableView{
					AssignTo: &a.connTV, AlternatingRowBG: true, ColumnsOrderable: true,
					Columns: []TableViewColumn{
						{Title: "Application", Width: 190}, {Title: "Target", Width: 250}, {Title: "Time/Status", Width: 90},
						{Title: "Rule : Proxy", Width: 250}, {Title: "Sent", Width: 80}, {Title: "Received", Width: 80},
					},
					Model: a.conns,
				},
				TextEdit{AssignTo: &a.logTE, ReadOnly: true, VScroll: true, MaxSize: Size{Height: 220}},
			}},
		},
		StatusBarItems: []StatusBarItem{{AssignTo: &a.sbi, Text: "Ready", Width: 760}},
	}.Create()
	if err != nil {
		walk.MsgBox(nil, "Shunt", err.Error(), walk.MsgBoxIconError)
		return
	}
	if ic, err := walk.NewIconFromResourceId(1); err == nil {
		a.mw.SetIcon(ic)
	} else if ic := a.icon("logo", brand.Logo, 32); ic != nil {
		a.mw.SetIcon(ic)
	}
	if ic, ok := a.mw.Icon().(*walk.Icon); ok {
		appIcon = ic
	}

	// Toolbar: 28 px icons instead of walk's 16 px default.
	dpi := a.mw.DPI()
	tbPx := 28 * dpi / 96
	if iml, err := walk.NewImageListForDPI(walk.SizeFrom96DPI(walk.Size{Width: 28, Height: 28}, dpi), 0, dpi); err == nil {
		a.tb.SetImageList(iml)
	}
	for act, img := range map[*walk.Action]func(int) *image.NRGBA{
		proxiesAct: brand.Servers, rulesAct: brand.Rules, dnsAct: brand.Globe, advAct: brand.Gear, checkAct: brand.Check,
	} {
		if ic := a.icon(fmt.Sprintf("%p", img), img, tbPx); ic != nil {
			act.SetImage(ic)
		}
	}
	// Grow the toolbar to fit the larger icons (walk sizes it for 16 px).
	a.tb.SendMessage(0x0421, 0, 0)                             // TB_AUTOSIZE
	if bs := uint32(a.tb.SendMessage(0x043A, 0, 0)); bs != 0 { // TB_GETBUTTONSIZE
		b := a.tb.BoundsPixels()
		b.Height = int(bs>>16) + 6*dpi/96
		a.tb.SetBoundsPixels(b)
	}
	if sz := a.mw.SizePixels(); sz.Width > 0 {
		a.mw.SetSizePixels(walk.Size{Width: sz.Width, Height: sz.Height + 1})
		a.mw.SetSizePixels(sz)
	}
	a.startAct = startAct
	a.updateState()

	a.mw.Closing().Attach(a.onClosing)
	a.setupTray()
	log.Printf("Welcome to Shunt %s. Profile: %s", version, a.path)
	if len(a.prof.Proxies) == 0 {
		log.Printf("No proxy servers are defined. Use Profile > Proxy Servers to add one, then press Start.")
	}

	go func() {
		for range time.Tick(time.Second) {
			a.mw.Synchronize(a.safe(a.refresh))
		}
	}()
	if autoStart {
		a.mw.Synchronize(a.safe(a.toggle))
	}
	a.mw.Run()
}

func (a *app) refresh() {
	a.logMu.Lock()
	s := a.logBuf.String()
	a.logBuf.Reset()
	a.logMu.Unlock()
	if s != "" {
		a.logTE.AppendText(strings.ReplaceAll(s, "\n", "\r\n"))
	}
	e := a.eng
	if e == nil {
		if len(a.conns.rows) > 0 {
			a.conns.rows = nil
			a.conns.PublishRowsReset()
		}
		if !a.busy {
			a.sbi.SetText("Ready (stopped)")
		}
		return
	}
	rows := e.Conns()
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	sel := a.connTV.CurrentIndex()
	a.conns.rows = rows
	a.conns.PublishRowsReset()
	if sel >= 0 && sel < len(rows) {
		a.connTV.SetCurrentIndex(sel)
	}
	if a.ni != nil {
		a.ni.SetToolTip(fmt.Sprintf("Shunt - running\n%d active connections\nSent %s, received %s", e.Active.Load(), size(e.Sent.Load()), size(e.Recv.Load())))
	}
	a.sbi.SetText(fmt.Sprintf("Running  |  %d active connections  |  %d total, %d failed  |  Sent %s  |  Received %s",
		e.Active.Load(), e.Total.Load(), e.Failed.Load(), size(e.Sent.Load()), size(e.Recv.Load())))
}

func (a *app) disconnect() {
	if i := a.connTV.CurrentIndex(); i >= 0 && i < len(a.conns.rows) {
		a.conns.rows[i].Disconnect()
	}
}

// ---- engine control ------------------------------------------------------------

// updateState refreshes the Start/Stop button and the status line.
func (a *app) updateState() {
	running := a.eng != nil
	px := 28 * a.mw.DPI() / 96
	text, img, art := "  Start", a.icon("start", brand.Start, px), brand.Start
	state, sub, color := "Stopped", "Press Start to send traffic through your proxification rules.", walk.RGB(100, 116, 139)
	if running {
		text, img, art = "  Stop", a.icon("stop", brand.Stop, px), brand.Stop
		state, sub, color = "Running", "All connections are processed by your proxification rules.", walk.RGB(22, 163, 74)
	}
	if a.busy {
		sub = "Please wait..."
	}
	a.startBtn.SetText(text)
	if bmp, err := walk.NewBitmapFromImageForDPI(art(px), a.mw.DPI()); err == nil {
		a.startBtn.SetImage(bmp)
	}
	if img != nil {
		a.startAct.SetImage(img)
	}
	a.startAct.SetText(strings.TrimSpace(text))
	a.startBtn.SetEnabled(!a.busy)
	a.startAct.SetEnabled(!a.busy)
	a.stateLbl.SetText(state)
	a.stateLbl.SetTextColor(color)
	a.stateSub.SetText(sub)
	if a.trayStart != nil {
		a.trayStart.SetText("&" + strings.TrimSpace(text))
		a.trayStart.SetEnabled(!a.busy)
	}
	if a.ni != nil && !running {
		a.ni.SetToolTip("Shunt - " + strings.ToLower(state))
	}
}

func (a *app) setBusy(b bool, status string) {
	a.busy = b
	if status != "" {
		a.stateLbl.SetText(status)
		a.sbi.SetText(status)
	}
	a.updateState()
	if b && status != "" {
		a.stateLbl.SetText(status)
	}
}

// toggle starts or stops the engine. The work runs in the background so the
// window stays responsive, and clicks are ignored while it is in progress.
func (a *app) toggle() {
	if a.busy {
		return
	}
	if a.eng != nil {
		a.stopEngine(nil)
		return
	}
	if !tun.Elevated() {
		if walk.MsgBox(a.mw, "Shunt", "Administrator rights are required to capture system traffic.\n\nRestart Shunt as administrator?", walk.MsgBoxYesNo|walk.MsgBoxIconQuestion) == walk.DlgCmdYes {
			exe, _ := os.Executable()
			verb, _ := windows.UTF16PtrFromString("runas")
			file, _ := windows.UTF16PtrFromString(exe)
			args, _ := windows.UTF16PtrFromString("-start")
			if windows.ShellExecute(0, verb, file, args, nil, windows.SW_SHOWNORMAL) == nil {
				a.quit()
			}
		}
		return
	}
	if !usesProxy(a.prof) && walk.MsgBox(a.mw, "Shunt", "No enabled rule sends traffic to a proxy server, so every connection will go directly.\n\nOpen Proxification Rules and set the Default rule to your proxy, or press Yes to start anyway.", walk.MsgBoxYesNo|walk.MsgBoxIconWarning) != walk.DlgCmdYes {
		return
	}
	a.startEngine()
}

func (a *app) startEngine() {
	a.setBusy(true, "Starting...")
	prof := a.prof.Clone()
	go func() {
		var e *core.Engine
		var err error
		func() {
			defer func() {
				if r := recover(); r != nil {
					err = fmt.Errorf("internal error: %v", r)
					log.Printf("internal error while starting: %v\n%s", r, debug.Stack())
				}
			}()
			if e, err = core.New(prof); err == nil {
				e.OnLoop = a.onLoop
				if err = e.StartTUN(); err != nil {
					e.Stop()
				}
			}
		}()
		a.mw.Synchronize(func() {
			if err != nil {
				log.Printf("Cannot start: %v", err)
				a.setBusy(false, "")
				walk.MsgBox(a.mw, "Shunt", "Cannot start:\n"+err.Error(), walk.MsgBoxIconError)
				return
			}
			a.eng = e
			a.setBusy(false, "")
		})
	}()
}

func (a *app) stopEngine(then func()) {
	e := a.eng
	a.eng = nil
	a.setBusy(true, "Stopping...")
	go func() {
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("internal error while stopping: %v\n%s", r, debug.Stack())
				}
			}()
			e.Stop()
		}()
		log.Printf("Stopped. Normal routing restored.")
		a.mw.Synchronize(func() {
			a.setBusy(false, "")
			if then != nil {
				then()
			}
		})
	}()
}

// onLoop is called by the engine when it finds a proxy server's own process
// among the captured connections. Like Proxifier, a Direct rule is added so
// the fix survives restarts.
func (a *app) onLoop(appName string) {
	a.mw.Synchronize(a.safe(func() {
		for _, r := range a.prof.Rules {
			for _, x := range strings.Split(strings.ToLower(r.Applications), ";") {
				if strings.Trim(strings.TrimSpace(x), `"`) == strings.ToLower(appName) && r.Action.Type == profile.ActDirect {
					return
				}
			}
		}
		p := a.prof.Clone()
		rule := profile.Rule{Name: appName + " [auto-created]", Enabled: true, Applications: appName, Action: profile.Action{Type: profile.ActDirect}}
		p.Rules = append([]profile.Rule{rule}, p.Rules...)
		a.prof = p
		if err := p.Save(a.path, a.kr); err != nil {
			log.Printf("Cannot save profile: %v", err)
		}
		log.Printf("Rule %q was created automatically: %s connects directly.", rule.Name, appName)
	}))
}

// setProfile validates and saves the profile, restarting the engine if it is
// running so the change takes effect.
func (a *app) setProfile(p *profile.Profile) {
	p.Normalize()
	if err := p.Validate(); err != nil {
		walk.MsgBox(a.mw, "Shunt", err.Error(), walk.MsgBoxIconWarning)
		return
	}
	a.prof = p
	if err := p.Save(a.path, a.kr); err != nil {
		log.Printf("Cannot save profile: %v", err)
	}
	if a.eng != nil && !a.busy {
		log.Printf("Profile changed, restarting.")
		a.stopEngine(a.startEngine)
	}
}

func (a *app) importProfile() {
	d := walk.FileDialog{Title: "Import Profile", Filter: "Profiles (*.ppx;*.json)|*.ppx;*.json|All files (*.*)|*.*"}
	if ok, _ := d.ShowOpen(a.mw); !ok {
		return
	}
	p, err := profile.Load(d.FilePath, a.kr)
	if p == nil {
		walk.MsgBox(a.mw, "Import Profile", err.Error(), walk.MsgBoxIconError)
		return
	}
	a.setProfile(p)
	log.Printf("Imported %s: %d proxies, %d chains, %d rules (proxy passwords are not imported from .ppx).", d.FilePath, len(p.Proxies), len(p.Chains), len(p.Rules))
}

func (a *app) exportProfile() {
	d := walk.FileDialog{Title: "Export Profile", Filter: "Proxifier profile (*.ppx)|*.ppx|Shunt profile (*.json)|*.json"}
	if ok, _ := d.ShowSave(a.mw); !ok {
		return
	}
	var b []byte
	var err error
	path := d.FilePath
	if strings.HasSuffix(strings.ToLower(path), ".json") {
		b, err = a.prof.Marshal(a.kr)
	} else {
		if !strings.HasSuffix(strings.ToLower(path), ".ppx") {
			path += ".ppx"
		}
		b, err = a.prof.MarshalPPX()
	}
	if err == nil {
		err = os.WriteFile(path, b, 0o644)
	}
	if err != nil {
		walk.MsgBox(a.mw, "Export Profile", err.Error(), walk.MsgBoxIconError)
	}
}

// checkDefaultProxy runs the proxy checker on the first proxy server.
func (a *app) checkDefaultProxy() {
	if len(a.prof.Proxies) == 0 {
		walk.MsgBox(a.mw, "Proxy Checker", "No proxy servers are defined yet. Add one in Proxy Servers.", walk.MsgBoxIconInformation)
		return
	}
	px := a.prof.Proxies[0]
	for _, r := range a.prof.Rules {
		if r.Action.Type == profile.ActProxy {
			if x := a.prof.ProxyByID(r.Action.ID); x != nil {
				px = *x
			}
		}
	}
	a.checkProxy(a.mw, &px)
}

func (a *app) about() {
	var dlg *walk.Dialog
	dpi := a.mw.DPI()
	logo, _ := walk.NewBitmapFromImageForDPI(brand.Logo(80*dpi/96), dpi)
	repo := strings.TrimPrefix(brand.RepoURL, "https://")
	Dialog{
		AssignTo: &dlg, Title: "About Shunt", Icon: a.mw.Icon(), Layout: VBox{Margins: Margins{Left: 18, Top: 16, Right: 18, Bottom: 12}, Spacing: 12},
		MinSize: Size{Width: 560, Height: 240},
		Children: []Widget{
			Composite{Layout: HBox{MarginsZero: true, Spacing: 16}, Children: []Widget{
				ImageView{Image: logo, Mode: ImageViewModeIdeal, MinSize: Size{Width: 80, Height: 80}, MaxSize: Size{Width: 80, Height: 80}},
				Composite{Layout: VBox{MarginsZero: true, Spacing: 4}, MinSize: Size{Width: 420}, Children: []Widget{
					Label{Text: "Shunt " + version, Font: Font{Family: "Segoe UI", PointSize: 16, Bold: true}},
					Label{Text: "Free and open source system-wide proxifier"},
					TextLabel{Text: "Author: " + brand.Author, MinSize: Size{Width: 300}},
					LinkLabel{Alignment: AlignHNearVCenter, MinSize: Size{Width: 300}, Text: `<a href="` + brand.RepoURL + `">` + repo + `</a>`, OnLinkActivated: func(l *walk.LinkLabelLink) { openURL(l.URL()) }},
					VSpacer{Size: 4},
					Label{Text: "MIT License. Uses Wintun (c) WireGuard LLC."},
				}},
			}},
			Composite{Layout: HBox{MarginsZero: true}, Children: []Widget{
				HSpacer{},
				PushButton{Text: "OK", OnClicked: func() { dlg.Accept() }},
			}},
		},
	}.Run(a.mw)
}
