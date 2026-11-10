package profile

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"
)

// Interoperability with Proxifier profile files (*.ppx, XML). Passwords in
// .ppx files are stored with Proxifier's own encryption and are therefore
// not imported; exported files contain no passwords.

type ppxEnabled struct {
	Enabled bool `xml:"enabled,attr"`
}

type ppxFile struct {
	XMLName  xml.Name `xml:"ProxifierProfile"`
	Version  string   `xml:"version,attr"`
	Platform string   `xml:"platform,attr"`
	Product  string   `xml:"product_id,attr"`
	MinVer   string   `xml:"product_minver,attr"`
	Options  struct {
		Resolve struct {
			AutoModeDetection ppxEnabled `xml:"AutoModeDetection"`
			ViaProxy          ppxEnabled `xml:"ViaProxy"`
			BlockNonATypes    ppxEnabled `xml:"BlockNonATypes"`
			ExclusionList     struct {
				OnlyFromListMode bool   `xml:"OnlyFromListMode,attr"`
				Value            string `xml:",chardata"`
			} `xml:"ExclusionList"`
			DnsUdpMode int `xml:"DnsUdpMode"`
		} `xml:"Resolve"`
		Encryption struct {
			Mode string `xml:"mode,attr"`
		} `xml:"Encryption"`
		ConnectionLoopDetection struct {
			Enabled bool `xml:"enabled,attr"`
			Resolve bool `xml:"resolve,attr"`
		} `xml:"ConnectionLoopDetection"`
		Udp struct {
			Mode string `xml:"mode,attr"`
		} `xml:"Udp"`
		LeakPreventionMode      ppxEnabled `xml:"LeakPreventionMode"`
		ProcessOtherUsers       ppxEnabled `xml:"ProcessOtherUsers"`
		ProcessServices         ppxEnabled `xml:"ProcessServices"`
		HandleDirectConnections ppxEnabled `xml:"HandleDirectConnections"`
		HttpProxiesSupport      ppxEnabled `xml:"HttpProxiesSupport"`
	} `xml:"Options"`
	ProxyList struct {
		Proxy []ppxProxy `xml:"Proxy"`
	} `xml:"ProxyList"`
	ChainList struct {
		Chain []ppxChain `xml:"Chain"`
	} `xml:"ChainList"`
	RuleList struct {
		Rule []ppxRule `xml:"Rule"`
	} `xml:"RuleList"`
}

type ppxProxy struct {
	ID      int    `xml:"id,attr"`
	Type    string `xml:"type,attr"`
	Auth    *struct {
		Enabled  bool   `xml:"enabled,attr"`
		Username string `xml:"Username"`
		Password string `xml:"Password,omitempty"`
	} `xml:"Authentication,omitempty"`
	Options int    `xml:"Options"`
	Port    int    `xml:"Port"`
	Address string `xml:"Address"`
	Label   string `xml:"Label,omitempty"`
}

type ppxChain struct {
	ID    int    `xml:"id,attr"`
	Type  string `xml:"type,attr"`
	Name  string `xml:"Name"`
	Proxy []struct {
		Enabled bool `xml:"enabled,attr"`
		ID      int  `xml:",chardata"`
	} `xml:"Proxy"`
	RedundancyTimeout     int   `xml:"RedundancyTimeout,omitempty"`
	RedundancyRecheck     *bool `xml:"RedundancyRecheck,omitempty"`
	RedundancyRecheckTime int   `xml:"RedundancyRecheckTime,omitempty"`
	RedundancyTryDirect   *bool `xml:"RedundancyTryDirect,omitempty"`
}

type ppxRule struct {
	Enabled bool `xml:"enabled,attr"`
	Action  struct {
		Type  string `xml:"type,attr"`
		Value string `xml:",chardata"`
	} `xml:"Action"`
	Applications string `xml:"Applications,omitempty"`
	Targets      string `xml:"Targets,omitempty"`
	Ports        string `xml:"Ports,omitempty"`
	Name         string `xml:"Name"`
}

var udpFromPPX = map[string]string{"mode_bypass": UDPBypass, "mode_block_443": UDPBlock443, "mode_block_quic": UDPBlock443, "mode_block_all": UDPBlockAll}
var udpToPPX = map[string]string{UDPBypass: "mode_bypass", UDPBlock443: "mode_block_443", UDPBlockAll: "mode_block_all"}
var chainFromPPX = map[string]string{"simple": ChainSimple, "redundancy": ChainRedundancy, "load_balancing": ChainLoadBalance}
var chainToPPX = map[string]string{ChainSimple: "simple", ChainRedundancy: "redundancy", ChainLoadBalance: "load_balancing"}

// ParsePPX converts a Proxifier profile into a Shunt profile.
func ParsePPX(b []byte) (*Profile, error) {
	var f ppxFile
	if err := xml.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("invalid Proxifier profile: %w", err)
	}
	p := &Profile{Version: CurrentVersion}
	o := &p.Options
	o.Resolve = Resolve{
		AutoDetect:    f.Options.Resolve.AutoModeDetection.Enabled,
		ViaProxy:      f.Options.Resolve.ViaProxy.Enabled,
		BlockNonA:     f.Options.Resolve.BlockNonATypes.Enabled,
		ExclusionList: strings.TrimSpace(f.Options.Resolve.ExclusionList.Value),
		OnlyFromList:  f.Options.Resolve.ExclusionList.OnlyFromListMode,
	}
	o.Encryption = EncBasic
	o.ConnectionLoopDetection = f.Options.ConnectionLoopDetection.Enabled
	o.ResolveLoopDetection = f.Options.ConnectionLoopDetection.Resolve
	o.UDPMode = udpFromPPX[f.Options.Udp.Mode]
	o.LeakPrevention = f.Options.LeakPreventionMode.Enabled
	o.ProcessOtherUsers = f.Options.ProcessOtherUsers.Enabled
	o.ProcessServices = f.Options.ProcessServices.Enabled
	o.HandleDirectConnections = f.Options.HandleDirectConnections.Enabled
	o.HTTPProxySupport = f.Options.HttpProxiesSupport.Enabled

	for _, x := range f.ProxyList.Proxy {
		px := Proxy{ID: x.ID, Type: strings.ToUpper(x.Type), Address: strings.TrimSpace(x.Address), Port: x.Port, Label: x.Label, UseHostname: true}
		if x.Auth != nil {
			px.AuthEnabled = x.Auth.Enabled
			px.Username = x.Auth.Username
		}
		if px.Type == HTTP {
			o.HTTPProxySupport = true
		}
		p.Proxies = append(p.Proxies, px)
	}
	for _, c := range f.ChainList.Chain {
		ch := Chain{ID: c.ID, Name: c.Name, Type: chainFromPPX[c.Type], TimeoutSec: c.RedundancyTimeout}
		if c.RedundancyRecheck != nil && *c.RedundancyRecheck {
			ch.RecheckSec = c.RedundancyRecheckTime
		}
		if c.RedundancyTryDirect != nil {
			ch.TryDirect = *c.RedundancyTryDirect
		}
		for _, it := range c.Proxy {
			ch.Proxies = append(ch.Proxies, ChainItem{ID: it.ID, Enabled: it.Enabled})
		}
		p.Chains = append(p.Chains, ch)
	}
	for _, r := range f.RuleList.Rule {
		rl := Rule{Name: r.Name, Enabled: r.Enabled, Applications: strings.TrimSpace(r.Applications), Targets: strings.TrimSpace(r.Targets), Ports: strings.TrimSpace(r.Ports)}
		id, _ := strconv.Atoi(strings.TrimSpace(r.Action.Value))
		switch r.Action.Type {
		case "Proxy":
			rl.Action = Action{Type: ActProxy, ID: id}
		case "Chain":
			rl.Action = Action{Type: ActChain, ID: id}
		case "Block":
			rl.Action = Action{Type: ActBlock}
		default:
			rl.Action = Action{Type: ActDirect}
		}
		p.Rules = append(p.Rules, rl)
	}
	p.Normalize()
	return p, nil
}

// MarshalPPX exports the profile in Proxifier's XML format (without passwords).
func (p *Profile) MarshalPPX() ([]byte, error) {
	var f ppxFile
	f.Version, f.Platform, f.Product, f.MinVer = "102", "Windows", "0", "400"
	o := p.Options
	f.Options.Resolve.AutoModeDetection.Enabled = o.Resolve.AutoDetect
	f.Options.Resolve.ViaProxy.Enabled = o.Resolve.ViaProxy
	f.Options.Resolve.BlockNonATypes.Enabled = o.Resolve.BlockNonA
	f.Options.Resolve.ExclusionList.Value = o.Resolve.ExclusionList
	f.Options.Resolve.ExclusionList.OnlyFromListMode = o.Resolve.OnlyFromList
	f.Options.Encryption.Mode = "basic"
	f.Options.ConnectionLoopDetection.Enabled = o.ConnectionLoopDetection
	f.Options.ConnectionLoopDetection.Resolve = o.ResolveLoopDetection
	f.Options.Udp.Mode = udpToPPX[o.UDPMode]
	f.Options.LeakPreventionMode.Enabled = o.LeakPrevention
	f.Options.ProcessOtherUsers.Enabled = o.ProcessOtherUsers
	f.Options.ProcessServices.Enabled = o.ProcessServices
	f.Options.HandleDirectConnections.Enabled = o.HandleDirectConnections
	f.Options.HttpProxiesSupport.Enabled = o.HTTPProxySupport
	for _, x := range p.Proxies {
		px := ppxProxy{ID: x.ID, Type: x.Type, Options: 48, Port: x.Port, Address: x.Address, Label: x.Label}
		if x.AuthEnabled {
			px.Auth = &struct {
				Enabled  bool   `xml:"enabled,attr"`
				Username string `xml:"Username"`
				Password string `xml:"Password,omitempty"`
			}{Enabled: true, Username: x.Username}
		}
		f.ProxyList.Proxy = append(f.ProxyList.Proxy, px)
	}
	for _, c := range p.Chains {
		ch := ppxChain{ID: c.ID, Type: chainToPPX[c.Type], Name: c.Name}
		for _, it := range c.Proxies {
			ch.Proxy = append(ch.Proxy, struct {
				Enabled bool `xml:"enabled,attr"`
				ID      int  `xml:",chardata"`
			}{it.Enabled, it.ID})
		}
		if c.Type == ChainRedundancy {
			re, td := c.RecheckSec > 0, c.TryDirect
			ch.RedundancyTimeout, ch.RedundancyRecheck, ch.RedundancyRecheckTime, ch.RedundancyTryDirect = c.TimeoutSec, &re, c.RecheckSec, &td
		}
		f.ChainList.Chain = append(f.ChainList.Chain, ch)
	}
	for _, r := range p.Rules {
		rl := ppxRule{Enabled: r.Enabled, Applications: r.Applications, Targets: r.Targets, Ports: r.Ports, Name: r.Name}
		rl.Action.Type = r.Action.Type
		if r.Action.Type == ActProxy || r.Action.Type == ActChain {
			rl.Action.Value = strconv.Itoa(r.Action.ID)
		}
		f.RuleList.Rule = append(f.RuleList.Rule, rl)
	}
	var buf bytes.Buffer
	buf.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` + "\n")
	enc := xml.NewEncoder(&buf)
	enc.Indent("", "\t")
	if err := enc.Encode(&f); err != nil {
		return nil, err
	}
	buf.WriteString("\n")
	return buf.Bytes(), nil
}
