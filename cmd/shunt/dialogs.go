package main

import (
	"context"
	"strconv"
	"strings"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"

	"shunt/internal/netif"
	"shunt/internal/profile"
	"shunt/internal/proxy"
)

func buttons(dlg **walk.Dialog, ok **walk.PushButton, accept func() bool) Composite {
	return Composite{Layout: HBox{MarginsZero: true}, Children: []Widget{
		PushButton{AssignTo: ok, Text: "OK", OnClicked: func() {
			if accept() {
				(*dlg).Accept()
			}
		}},
		HSpacer{},
		PushButton{Text: "Cancel", OnClicked: func() { (*dlg).Cancel() }},
	}}
}

type listModel struct {
	walk.TableModelBase
	n       func() int
	value   func(row, col int) interface{}
	checked func(row int) *bool
}

func (m *listModel) RowCount() int              { return m.n() }
func (m *listModel) Value(r, c int) interface{} { return m.value(r, c) }
func (m *listModel) Checked(r int) bool         { return m.checked != nil && *m.checked(r) }
func (m *listModel) SetChecked(r int, v bool) error {
	if m.checked != nil {
		*m.checked(r) = v
	}
	return nil
}

var proxyTypes = []string{profile.SOCKS5, profile.SOCKS4, profile.HTTPS, profile.HTTP}

func index(list []string, s string) int {
	for i, v := range list {
		if v == s {
			return i
		}
	}
	return 0
}

func (a *app) proxyDialog(owner walk.Form, px *profile.Proxy) bool {
	var dlg *walk.Dialog
	var ok *walk.PushButton
	var addr, port, user, pass *walk.LineEdit
	var typ *walk.ComboBox
	var auth, s4a *walk.CheckBox
	read := func() (*profile.Proxy, bool) {
		n, err := strconv.Atoi(strings.TrimSpace(port.Text()))
		if strings.TrimSpace(addr.Text()) == "" || err != nil || n < 1 || n > 65535 {
			walk.MsgBox(dlg, "Proxy Server", "Please enter a valid address and port (1-65535).", walk.MsgBoxIconWarning)
			return nil, false
		}
		c := *px
		c.Address, c.Port, c.Type = strings.TrimSpace(addr.Text()), n, proxyTypes[max(typ.CurrentIndex(), 0)]
		c.AuthEnabled, c.Username, c.Password, c.Socks4A, c.UseHostname = auth.Checked(), user.Text(), pass.Text(), s4a.Checked(), true
		return &c, true
	}
	portText := ""
	if px.Port > 0 {
		portText = strconv.Itoa(px.Port)
	}
	res, _ := Dialog{
		AssignTo: &dlg, Title: "Proxy Server", DefaultButton: &ok, MinSize: Size{Width: 420}, Layout: VBox{},
		Children: []Widget{
			GroupBox{Title: "Server", Layout: Grid{Columns: 4}, Children: []Widget{
				Label{Text: "Address:"}, LineEdit{AssignTo: &addr, Text: px.Address},
				Label{Text: "Port:"}, LineEdit{AssignTo: &port, Text: portText, MaxSize: Size{Width: 60}},
				Label{Text: "Protocol:"}, ComboBox{AssignTo: &typ, Model: proxyTypes, CurrentIndex: index(proxyTypes, px.Type), ColumnSpan: 3},
			}},
			GroupBox{Title: "Authentication", Layout: Grid{Columns: 2}, Children: []Widget{
				CheckBox{AssignTo: &auth, Text: "Enable", Checked: px.AuthEnabled, ColumnSpan: 2},
				Label{Text: "Username:"}, LineEdit{AssignTo: &user, Text: px.Username},
				Label{Text: "Password:"}, LineEdit{AssignTo: &pass, Text: px.Password, PasswordMode: true},
			}},
			GroupBox{Title: "Options", Layout: VBox{}, Children: []Widget{
				CheckBox{AssignTo: &s4a, Text: "Use SOCKS 4A extension (remote hostname resolving, SOCKS4 only)", Checked: px.Socks4A},
			}},
			Composite{Layout: HBox{MarginsZero: true}, Children: []Widget{
				PushButton{AssignTo: &ok, Text: "OK", OnClicked: func() {
					if c, good := read(); good {
						*px = *c
						dlg.Accept()
					}
				}},
				PushButton{Text: "Check", OnClicked: func() {
					if c, good := read(); good {
						a.checkProxy(dlg, c)
					}
				}},
				HSpacer{},
				PushButton{Text: "Cancel", OnClicked: func() { dlg.Cancel() }},
			}},
		},
	}.Run(owner)
	return res == walk.DlgCmdOK
}

// checkProxy runs the proxy checker and shows its report.
func (a *app) checkProxy(owner walk.Form, px *profile.Proxy) {
	var dlg *walk.Dialog
	var out *walk.TextEdit
	Dialog{
		AssignTo: &dlg, Title: "Proxy Checker - " + px.HostPort(), MinSize: Size{Width: 620, Height: 380}, Layout: VBox{},
		Children: []Widget{
			TextEdit{AssignTo: &out, ReadOnly: true, VScroll: true, Text: "Testing " + px.Type + " " + px.HostPort() + " ...\r\n"},
			Composite{Layout: HBox{MarginsZero: true}, Children: []Widget{HSpacer{}, PushButton{Text: "Close", OnClicked: func() { dlg.Accept() }}}},
		},
	}.Create(owner)
	go func() {
		res := proxy.Check(context.Background(), netif.Dialer(func() netif.Binding { return netif.Binding{} }), px, proxy.DefaultCheckSettings())
		dlg.Synchronize(func() { out.SetText(strings.Join(res.Lines, "\r\n") + "\r\n\r\n" + res.Verdict) })
	}()
	dlg.Run()
}

func (a *app) proxiesDialog() {
	p := a.prof.Clone()
	var dlg *walk.Dialog
	var ok *walk.PushButton
	var tv *walk.TableView
	m := &listModel{n: func() int { return len(p.Proxies) }, value: func(r, c int) interface{} {
		x := p.Proxies[r]
		return []interface{}{x.Address, x.Port, x.Type, map[bool]string{true: x.Username, false: ""}[x.AuthEnabled]}[c]
	}}
	edit := func() {
		if i := tv.CurrentIndex(); i >= 0 && a.proxyDialog(dlg, &p.Proxies[i]) {
			m.PublishRowsReset()
		}
	}
	res, _ := Dialog{
		AssignTo: &dlg, Title: "Proxy Servers", DefaultButton: &ok, MinSize: Size{Width: 560, Height: 340}, Layout: VBox{},
		Children: []Widget{
			Composite{Layout: HBox{MarginsZero: true}, Children: []Widget{
				TableView{AssignTo: &tv, Model: m, OnItemActivated: edit, Columns: []TableViewColumn{
					{Title: "Address", Width: 180}, {Title: "Port", Width: 60}, {Title: "Type", Width: 80}, {Title: "Username", Width: 110}}},
				Composite{Layout: VBox{MarginsZero: true}, Children: []Widget{
					PushButton{Text: "Add...", OnClicked: func() {
						px := profile.Proxy{ID: p.NextID(), Type: profile.SOCKS5, UseHostname: true}
						if a.proxyDialog(dlg, &px) {
							p.Proxies = append(p.Proxies, px)
							m.PublishRowsReset()
							if len(p.Proxies) == 1 && walk.MsgBox(dlg, "Proxy Servers", "Do you want Shunt to use this proxy by default for all connections?", walk.MsgBoxYesNo|walk.MsgBoxIconQuestion) == walk.DlgCmdYes {
								p.Rules[len(p.Rules)-1].Action = profile.Action{Type: profile.ActProxy, ID: px.ID}
							}
						}
					}},
					PushButton{Text: "Edit...", OnClicked: edit},
					PushButton{Text: "Remove", OnClicked: func() {
						i := tv.CurrentIndex()
						if i < 0 {
							return
						}
						id := p.Proxies[i].ID
						if used := p.RulesUsing(id); len(used) > 0 {
							if walk.MsgBox(dlg, "Proxy Removal", "This proxy is the Action of rule(s): "+strings.Join(used, ", ")+".\n\nSet these rules to Direct and remove the proxy?", walk.MsgBoxYesNo|walk.MsgBoxIconWarning) != walk.DlgCmdYes {
								return
							}
							for j := range p.Rules {
								if p.Rules[j].Action.Type == profile.ActProxy && p.Rules[j].Action.ID == id {
									p.Rules[j].Action = profile.Action{Type: profile.ActDirect}
								}
							}
						}
						for j := range p.Chains {
							c := &p.Chains[j]
							for k := len(c.Proxies) - 1; k >= 0; k-- {
								if c.Proxies[k].ID == id {
									c.Proxies = append(c.Proxies[:k], c.Proxies[k+1:]...)
								}
							}
						}
						p.Proxies = append(p.Proxies[:i], p.Proxies[i+1:]...)
						m.PublishRowsReset()
					}},
					PushButton{Text: "Check...", OnClicked: func() {
						if i := tv.CurrentIndex(); i >= 0 {
							a.checkProxy(dlg, &p.Proxies[i])
						}
					}},
					VSpacer{},
				}},
			}},
			Label{Text: "Proxy chains (simple, redundancy, load balancing) are supported by the engine and are edited in the profile file."},
			buttons(&dlg, &ok, func() bool { return true }),
		},
	}.Run(a.mw)
	if res == walk.DlgCmdOK {
		a.setProfile(p)
	}
}

func actionChoices(p *profile.Profile) ([]string, []profile.Action) {
	names := []string{"Direct", "Block"}
	acts := []profile.Action{{Type: profile.ActDirect}, {Type: profile.ActBlock}}
	for _, x := range p.Proxies {
		a := profile.Action{Type: profile.ActProxy, ID: x.ID}
		names, acts = append(names, p.ActionLabel(a)), append(acts, a)
	}
	for _, c := range p.Chains {
		a := profile.Action{Type: profile.ActChain, ID: c.ID}
		names, acts = append(names, p.ActionLabel(a)), append(acts, a)
	}
	return names, acts
}

func (a *app) ruleDialog(owner walk.Form, p *profile.Profile, r *profile.Rule, isDefault bool) bool {
	var dlg *walk.Dialog
	var ok *walk.PushButton
	var name *walk.LineEdit
	var apps, targets, ports *walk.TextEdit
	var enabled *walk.CheckBox
	var action *walk.ComboBox
	names, acts := actionChoices(p)
	cur := 0
	for i, x := range acts {
		if x == r.Action {
			cur = i
		}
	}
	res, _ := Dialog{
		AssignTo: &dlg, Title: "Proxification Rule", DefaultButton: &ok, MinSize: Size{Width: 520}, Layout: VBox{},
		Children: []Widget{
			Composite{Layout: HBox{MarginsZero: true}, Children: []Widget{
				Label{Text: "Name:"}, LineEdit{AssignTo: &name, Text: r.Name},
				CheckBox{AssignTo: &enabled, Text: "Enabled", Checked: r.Enabled, Enabled: !isDefault},
			}},
			GroupBox{Title: "Applications", Layout: VBox{}, Enabled: !isDefault, Children: []Widget{
				TextEdit{AssignTo: &apps, Text: r.Applications, MinSize: Size{Height: 44}},
				Composite{Layout: HBox{MarginsZero: true}, Children: []Widget{
					Label{Text: `Example: iexplore.exe; "C:\some app.exe"; fire*.exe; *.bin   (empty = Any)`}, HSpacer{},
					PushButton{Text: "Browse...", OnClicked: func() {
						d := walk.FileDialog{Title: "Select application", Filter: "Applications (*.exe)|*.exe|All files (*.*)|*.*"}
						if good, _ := d.ShowOpen(dlg); good {
							n := d.FilePath[strings.LastIndexAny(d.FilePath, `\/`)+1:]
							if strings.Contains(n, " ") {
								n = `"` + n + `"`
							}
							if t := strings.TrimSpace(apps.Text()); t != "" {
								n = t + "; " + n
							}
							apps.SetText(n)
						}
					}},
				}},
			}},
			GroupBox{Title: "Target hosts", Layout: VBox{}, Enabled: !isDefault, Children: []Widget{
				TextEdit{AssignTo: &targets, Text: r.Targets, MinSize: Size{Height: 44}},
				Label{Text: "Example: 127.0.0.1; *.example.com; 192.168.1.*; 10.1.0.0-10.5.255.255   (empty = Any)"},
			}},
			GroupBox{Title: "Target ports", Layout: VBox{}, Enabled: !isDefault, Children: []Widget{
				TextEdit{AssignTo: &ports, Text: r.Ports, MaxSize: Size{Height: 26}},
				Label{Text: "Example: 80; 8000-9000; 3128   (empty = Any)"},
			}},
			Composite{Layout: HBox{MarginsZero: true}, Children: []Widget{
				Label{Text: "Action:"}, ComboBox{AssignTo: &action, Model: names, CurrentIndex: cur},
			}},
			buttons(&dlg, &ok, func() bool {
				if strings.TrimSpace(name.Text()) == "" {
					walk.MsgBox(dlg, "Proxification Rule", "Please enter a rule name.", walk.MsgBoxIconWarning)
					return false
				}
				r.Name, r.Enabled, r.Action = strings.TrimSpace(name.Text()), enabled.Checked(), acts[max(action.CurrentIndex(), 0)]
				if !isDefault {
					clean := func(s string) string { return strings.Join(strings.Fields(strings.ReplaceAll(s, "\r\n", " ")), " ") }
					r.Applications, r.Targets, r.Ports = clean(apps.Text()), clean(targets.Text()), clean(ports.Text())
				}
				return true
			}),
		},
	}.Run(owner)
	return res == walk.DlgCmdOK
}

func (a *app) rulesDialog() {
	p := a.prof.Clone()
	var dlg *walk.Dialog
	var ok *walk.PushButton
	var tv *walk.TableView
	anyIf := func(s string) string {
		if s == "" {
			return "Any"
		}
		return s
	}
	m := &listModel{n: func() int { return len(p.Rules) },
		value: func(r, c int) interface{} {
			x := p.Rules[r]
			return []string{x.Name, anyIf(x.Applications), anyIf(x.Targets), anyIf(x.Ports), p.ActionLabel(x.Action)}[c]
		},
		checked: func(r int) *bool {
			if r == len(p.Rules)-1 {
				p.Rules[r].Enabled = true
			}
			return &p.Rules[r].Enabled
		}}
	last := func() int { return len(p.Rules) - 1 }
	edit := func() {
		if i := tv.CurrentIndex(); i >= 0 && a.ruleDialog(dlg, p, &p.Rules[i], i == last()) {
			m.PublishRowsReset()
		}
	}
	move := func(d int) {
		i := tv.CurrentIndex()
		j := i + d
		if i < 0 || i >= last() || j < 0 || j >= last() {
			return
		}
		p.Rules[i], p.Rules[j] = p.Rules[j], p.Rules[i]
		m.PublishRowsReset()
		tv.SetCurrentIndex(j)
	}
	insert := func(r profile.Rule) {
		p.Rules = append(p.Rules[:last()], append([]profile.Rule{r}, p.Rules[last():]...)...)
		m.PublishRowsReset()
	}
	res, _ := Dialog{
		AssignTo: &dlg, Title: "Proxification Rules", DefaultButton: &ok, MinSize: Size{Width: 860, Height: 420}, Layout: VBox{},
		Children: []Widget{
			Composite{Layout: HBox{MarginsZero: true}, Children: []Widget{
				TableView{AssignTo: &tv, Model: m, CheckBoxes: true, OnItemActivated: edit, Columns: []TableViewColumn{
					{Title: "Name", Width: 170}, {Title: "Applications", Width: 170}, {Title: "Target hosts", Width: 190},
					{Title: "Target ports", Width: 90}, {Title: "Action", Width: 190}}},
				Composite{Layout: VBox{MarginsZero: true}, Children: []Widget{
					VSpacer{}, PushButton{Text: "▲", MaxSize: Size{Width: 32}, OnClicked: func() { move(-1) }},
					PushButton{Text: "▼", MaxSize: Size{Width: 32}, OnClicked: func() { move(1) }}, VSpacer{},
				}},
			}},
			Composite{Layout: HBox{MarginsZero: true}, Children: []Widget{
				PushButton{Text: "Add...", OnClicked: func() {
					r := profile.Rule{Name: "New", Enabled: true, Action: profile.Action{Type: profile.ActDirect}}
					if a.ruleDialog(dlg, p, &r, false) {
						insert(r)
					}
				}},
				PushButton{Text: "Clone", OnClicked: func() {
					if i := tv.CurrentIndex(); i >= 0 && i < last() {
						r := p.Rules[i]
						r.Name += " (copy)"
						insert(r)
					}
				}},
				PushButton{Text: "Edit...", OnClicked: edit},
				PushButton{Text: "Remove", OnClicked: func() {
					i := tv.CurrentIndex()
					if i == last() {
						walk.MsgBox(dlg, "Proxification Rules", "Shunt uses the Default rule when no other rule matches, so it cannot be removed.", walk.MsgBoxIconInformation)
					} else if i >= 0 {
						p.Rules = append(p.Rules[:i], p.Rules[i+1:]...)
						m.PublishRowsReset()
					}
				}},
				HSpacer{},
			}},
			Label{Text: "Rules are processed from top to bottom. Use the arrows at the right to change the order.\nUse check boxes to enable/disable a rule."},
			buttons(&dlg, &ok, func() bool { return true }),
		},
	}.Run(a.mw)
	if res == walk.DlgCmdOK {
		a.setProfile(p)
	}
}

func (a *app) dnsDialog() {
	p := a.prof.Clone()
	r := &p.Options.Resolve
	var dlg *walk.Dialog
	var ok *walk.PushButton
	var auto, via, nonA *walk.CheckBox
	var mode *walk.ComboBox
	var list *walk.TextEdit
	onlyIdx := 0
	if r.OnlyFromList {
		onlyIdx = 1
	}
	res, _ := Dialog{
		AssignTo: &dlg, Title: "Name Resolution", DefaultButton: &ok, MinSize: Size{Width: 540}, Layout: VBox{},
		Children: []Widget{
			GroupBox{Title: "Shunt DNS settings", Layout: VBox{}, Children: []Widget{
				CheckBox{AssignTo: &auto, Text: "Detect DNS settings automatically (resolve through proxy when a rule uses one)", Checked: r.AutoDetect, OnCheckedChanged: func() {
					// The handler can fire while the dialog is still being built.
					if via != nil && auto != nil {
						via.SetEnabled(!auto.Checked())
					}
				}},
				CheckBox{AssignTo: &via, Text: "Resolve hostnames through proxy", Checked: r.ViaProxy, Enabled: !r.AutoDetect},
				CheckBox{AssignTo: &nonA, Text: "Block non A/AAAA queries if DNS goes through proxy", Checked: r.BlockNonA},
			}},
			GroupBox{Title: "Note", Layout: VBox{}, Children: []Widget{
				Label{Text: "It is impossible to get real IP addresses through a proxy.\nShunt assigns \"fake\" IP addresses (198.18.*.*) that are only valid while it is running."},
			}},
			GroupBox{Title: "DNS name list", Layout: VBox{}, Children: []Widget{
				ComboBox{AssignTo: &mode, Model: []string{"Do NOT resolve the following through proxy", "Resolve ONLY the following through proxy"}, CurrentIndex: onlyIdx},
				TextEdit{AssignTo: &list, Text: r.ExclusionList, MinSize: Size{Height: 50}},
				Label{Text: "Example: localhost; *.example.com; %ComputerName%; %SimpleHostnames%"},
			}},
			buttons(&dlg, &ok, func() bool {
				r.AutoDetect, r.ViaProxy, r.BlockNonA = auto.Checked(), via.Checked(), nonA.Checked()
				r.OnlyFromList, r.ExclusionList = mode.CurrentIndex() == 1, strings.TrimSpace(list.Text())
				return true
			}),
		},
	}.Run(a.mw)
	if res == walk.DlgCmdOK {
		a.setProfile(p)
	}
}

func (a *app) advancedDialog() {
	p := a.prof.Clone()
	o := &p.Options
	var dlg *walk.Dialog
	var ok *walk.PushButton
	var users, svcs, httpx, leak, direct, loop *walk.CheckBox
	var udp, enc *walk.ComboBox
	udpModes := []string{profile.UDPBypass, profile.UDPBlock443, profile.UDPBlockAll}
	encModes := []string{profile.EncDisabled, profile.EncBasic, profile.EncUser}
	res, _ := Dialog{
		AssignTo: &dlg, Title: "Advanced", DefaultButton: &ok, MinSize: Size{Width: 520}, Layout: VBox{},
		Children: []Widget{
			GroupBox{Title: "Services and other users", Layout: VBox{}, Children: []Widget{
				CheckBox{AssignTo: &users, Text: "Applications run by other users on this computer", Checked: o.ProcessOtherUsers},
				CheckBox{AssignTo: &svcs, Text: "Windows services and other system processes", Checked: o.ProcessServices},
			}},
			GroupBox{Title: "Connections", Layout: VBox{}, Children: []Widget{
				CheckBox{AssignTo: &httpx, Text: "Enable HTTP proxy servers support (HTTP connections only)", Checked: o.HTTPProxySupport},
				CheckBox{AssignTo: &leak, Text: "DNS and IP leak prevention mode", Checked: o.LeakPrevention},
				CheckBox{AssignTo: &direct, Text: "Handle direct connections (show them in the list)", Checked: o.HandleDirectConnections},
				CheckBox{AssignTo: &loop, Text: "Infinite connection loop detection", Checked: o.ConnectionLoopDetection},
			}},
			GroupBox{Title: "UDP traffic", Layout: VBox{}, Children: []Widget{
				ComboBox{AssignTo: &udp, CurrentIndex: index(udpModes, o.UDPMode), Model: []string{
					"Bypass UDP traffic", "Block traffic to UDP port 443 (QUIC) if matched the rule", "Block traffic to all UDP ports if matched the rule"}},
			}},
			GroupBox{Title: "Profile passwords encryption", Layout: VBox{}, Children: []Widget{
				ComboBox{AssignTo: &enc, CurrentIndex: index(encModes, o.Encryption), Model: []string{
					"Disabled - passwords are saved in plain text", "Basic - encryption with a static key", "Current user account - only you can read the passwords"}},
			}},
			buttons(&dlg, &ok, func() bool {
				o.ProcessOtherUsers, o.ProcessServices, o.HTTPProxySupport = users.Checked(), svcs.Checked(), httpx.Checked()
				o.LeakPrevention, o.HandleDirectConnections, o.ConnectionLoopDetection = leak.Checked(), direct.Checked(), loop.Checked()
				o.UDPMode, o.Encryption = udpModes[max(udp.CurrentIndex(), 0)], encModes[max(enc.CurrentIndex(), 0)]
				return true
			}),
		},
	}.Run(a.mw)
	if res == walk.DlgCmdOK {
		a.setProfile(p)
	}
}
