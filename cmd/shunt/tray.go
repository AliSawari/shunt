package main

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
	"github.com/lxn/win"

	"shunt/internal/tun"
)

// appIcon is the Shunt icon, shared by the main window and every dialog.
var appIcon *walk.Icon

// Close button behaviour.
const (
	closeAsk  = "ask"
	closeTray = "tray"
	closeExit = "exit"
)

// uiSettings are per-user window preferences (not part of the profile).
type uiSettings struct {
	CloseAction   string `json:"closeAction"`
	TrayHintShown bool   `json:"trayHintShown"`
}

func settingsPath() string { return filepath.Join(configDir(), "settings.json") }

func loadSettings() uiSettings {
	s := uiSettings{CloseAction: closeAsk}
	if b, err := os.ReadFile(settingsPath()); err == nil {
		json.Unmarshal(b, &s)
	}
	switch s.CloseAction {
	case closeTray, closeExit:
	default:
		s.CloseAction = closeAsk
	}
	return s
}

func (a *app) saveSettings() {
	b, _ := json.MarshalIndent(a.settings, "", "  ")
	if err := os.WriteFile(settingsPath(), b, 0o644); err != nil {
		log.Printf("Cannot save settings: %v", err)
	}
}

// setupTray creates the notification area icon and its menu.
func (a *app) setupTray() {
	ni, err := walk.NewNotifyIcon(a.mw)
	if err != nil {
		log.Printf("System tray icon unavailable: %v", err)
		return
	}
	a.ni = ni
	if appIcon != nil {
		ni.SetIcon(appIcon)
	}
	ni.SetToolTip("Shunt - stopped")
	ni.MouseDown().Attach(func(x, y int, button walk.MouseButton) {
		if button == walk.LeftButton {
			a.showWindow()
		}
	})
	add := func(text string, f func()) *walk.Action {
		act := walk.NewAction()
		act.SetText(text)
		act.Triggered().Attach(a.safe(f))
		ni.ContextMenu().Actions().Add(act)
		return act
	}
	open := add("&Open Shunt", a.showWindow)
	open.SetDefault(true)
	ni.ContextMenu().Actions().Add(walk.NewSeparatorAction())
	a.trayStart = add("&Start", func() {
		a.showWindowIfNeededForPrompt()
		a.toggle()
	})
	add("&Proxy Servers...", func() { a.showWindow(); a.proxiesDialog() })
	add("Proxification &Rules...", func() { a.showWindow(); a.rulesDialog() })
	ni.ContextMenu().Actions().Add(walk.NewSeparatorAction())
	add("E&xit", a.quit)
	ni.SetVisible(true)
}

// showWindow brings the main window back from the tray.
func (a *app) showWindow() {
	a.mw.Show()
	h := a.mw.Handle()
	if win.IsIconic(h) {
		win.ShowWindow(h, win.SW_RESTORE)
	}
	win.SetForegroundWindow(h)
}

// showWindowIfNeededForPrompt shows the window when Start will need to ask
// something (administrator rights, no proxy rule), so the question is visible.
func (a *app) showWindowIfNeededForPrompt() {
	if a.eng == nil && (!usesProxy(a.prof) || !tun.Elevated()) {
		a.showWindow()
	}
}

func (a *app) hideToTray() {
	if a.ni == nil {
		a.mw.SetVisible(false)
		return
	}
	a.mw.Hide()
	if !a.settings.TrayHintShown {
		a.ni.ShowInfo("Shunt is still running", "Shunt keeps working in the notification area. Right-click the icon to exit.")
		a.settings.TrayHintShown = true
		a.saveSettings()
	}
}

// quit exits Shunt for real: the tunnel is stopped and the tray icon removed.
func (a *app) quit() {
	a.quitting = true
	a.mw.Close()
}

// onClosing decides what the window's close button does.
func (a *app) onClosing(canceled *bool, reason walk.CloseReason) {
	// walk reports every close as CloseReasonUnknown, so the reason cannot tell
	// the title-bar button from a programmatic close; quit() sets a.quitting.
	if !a.quitting && a.ni != nil {
		action := a.settings.CloseAction
		if action == closeAsk {
			var remember bool
			action, remember = a.askClose()
			if action == "" { // Cancel
				*canceled = true
				return
			}
			if remember {
				a.settings.CloseAction = action
				a.saveSettings()
				if a.trayCloseAct != nil {
					a.trayCloseAct.SetChecked(action == closeTray)
				}
			}
		}
		if action == closeTray {
			*canceled = true
			a.hideToTray()
			return
		}
	}
	if a.eng != nil {
		a.eng.Stop()
		a.eng = nil
	}
	if a.ni != nil {
		a.ni.Dispose()
		a.ni = nil
	}
}

// askClose asks whether the close button should exit or minimize to tray.
// It returns "" when the user cancels.
func (a *app) askClose() (string, bool) {
	var dlg *walk.Dialog
	var trayBtn *walk.PushButton
	var rememberCB *walk.CheckBox
	choice := ""
	msg := "Do you want to exit Shunt, or keep it running in the notification area?"
	if a.eng != nil {
		msg = "Shunt is running. Exiting stops the tunnel and restores normal routing.\n\nKeep Shunt running in the notification area instead?"
	}
	Dialog{
		AssignTo: &dlg, Title: "Close Shunt", Icon: appIcon, DefaultButton: &trayBtn, MinSize: Size{Width: 460},
		Layout: VBox{Margins: Margins{Left: 16, Top: 14, Right: 16, Bottom: 12}, Spacing: 12},
		Children: []Widget{
			Label{Text: msg},
			CheckBox{AssignTo: &rememberCB, Alignment: AlignHNearVCenter, Text: "Remember my choice (change it later in View menu)"},
			Composite{Layout: HBox{MarginsZero: true}, Children: []Widget{
				HSpacer{},
				PushButton{AssignTo: &trayBtn, Text: "Minimize to Tray", OnClicked: func() { choice = closeTray; dlg.Accept() }},
				PushButton{Text: "Exit Shunt", OnClicked: func() { choice = closeExit; dlg.Accept() }},
				PushButton{Text: "Cancel", OnClicked: func() { dlg.Cancel() }},
			}},
		},
	}.Run(a.mw)
	return choice, choice != "" && rememberCB.Checked()
}
