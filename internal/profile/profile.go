// Package profile defines the Shunt profile model: proxy servers, proxy
// chains, proxification rules and engine options.
package profile

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Proxy protocol types.
const (
	SOCKS5 = "SOCKS5"
	SOCKS4 = "SOCKS4"
	HTTPS  = "HTTPS" // HTTP proxy with CONNECT tunnelling
	HTTP   = "HTTP"  // plain HTTP proxy (HTTP traffic only)
)

// Rule action types.
const (
	ActDirect = "Direct"
	ActBlock  = "Block"
	ActProxy  = "Proxy"
	ActChain  = "Chain"
)

// Chain types.
const (
	ChainSimple      = "simple"
	ChainRedundancy  = "redundancy"
	ChainLoadBalance = "loadbalance"
)

// UDP handling modes.
const (
	UDPBypass   = "bypass"
	UDPBlock443 = "block443"
	UDPBlockAll = "blockall"
)

// Password encryption modes.
const (
	EncDisabled = "disabled"
	EncBasic    = "basic"
	EncUser     = "user"
	EncMaster   = "master"
)

type Resolve struct {
	AutoDetect    bool   `json:"autoDetect"`
	ViaProxy      bool   `json:"viaProxy"`
	BlockNonA     bool   `json:"blockNonA"`
	ExclusionList string `json:"exclusionList"`
	OnlyFromList  bool   `json:"onlyFromList"`
}

type Options struct {
	Resolve                 Resolve `json:"resolve"`
	Encryption              string  `json:"encryption"`
	ConnectionLoopDetection bool    `json:"connectionLoopDetection"`
	ResolveLoopDetection    bool    `json:"resolveLoopDetection"`
	UDPMode                 string  `json:"udpMode"`
	LeakPrevention          bool    `json:"leakPrevention"`
	ProcessOtherUsers       bool    `json:"processOtherUsers"`
	ProcessServices         bool    `json:"processServices"`
	HandleDirectConnections bool    `json:"handleDirectConnections"`
	HTTPProxySupport        bool    `json:"httpProxySupport"`
}

type Proxy struct {
	ID          int    `json:"id"`
	Type        string `json:"type"`
	Address     string `json:"address"`
	Port        int    `json:"port"`
	Label       string `json:"label,omitempty"`
	AuthEnabled bool   `json:"authEnabled"`
	Username    string `json:"username,omitempty"`
	// Password is the clear text password in memory. On disk it is stored
	// in PasswordEnc according to Options.Encryption.
	Password    string `json:"password,omitempty"`
	PasswordEnc string `json:"passwordEnc,omitempty"`
	PasswordSet bool   `json:"passwordSet,omitempty"` // API only
	Socks4A     bool   `json:"socks4a,omitempty"`
	UserAgent   string `json:"userAgent,omitempty"`
	// UseHostname sends the target hostname (when known) to the proxy
	// instead of an IP address.
	UseHostname bool `json:"useHostname"`
}

func (p *Proxy) HostPort() string { return fmt.Sprintf("%s:%d", bracket(p.Address), p.Port) }

func (p *Proxy) Display() string {
	if p.Label != "" {
		return p.Label
	}
	return p.HostPort()
}

func bracket(h string) string {
	if strings.Contains(h, ":") && !strings.HasPrefix(h, "[") {
		return "[" + h + "]"
	}
	return h
}

type ChainItem struct {
	ID      int  `json:"id"`
	Enabled bool `json:"enabled"`
}

type Chain struct {
	ID      int         `json:"id"`
	Name    string      `json:"name"`
	Type    string      `json:"type"`
	Proxies []ChainItem `json:"proxies"`
	// Redundancy options.
	TimeoutSec int  `json:"timeoutSec,omitempty"`
	RecheckSec int  `json:"recheckSec,omitempty"` // 0 = never recheck
	TryDirect  bool `json:"tryDirect,omitempty"`
	// Load-balancing options.
	StickyPID bool `json:"stickyPid,omitempty"`
}

type Action struct {
	Type string `json:"type"`
	ID   int    `json:"id,omitempty"`
}

type Rule struct {
	Name         string `json:"name"`
	Enabled      bool   `json:"enabled"`
	Applications string `json:"applications,omitempty"`
	Targets      string `json:"targets,omitempty"`
	Ports        string `json:"ports,omitempty"`
	Action       Action `json:"action"`
	// Interface optionally pins matching connections to a network interface.
	Interface string `json:"interface,omitempty"`
	// IfDownIgnore: when the pinned interface is down, skip the rule
	// (true) or fall back to the system default interface (false).
	IfDownIgnore bool `json:"ifDownIgnore,omitempty"`
}

type Profile struct {
	Version int     `json:"version"`
	Options Options `json:"options"`
	Proxies []Proxy `json:"proxies"`
	Chains  []Chain `json:"chains"`
	Rules   []Rule  `json:"rules"`
}

const CurrentVersion = 1

// Default returns a new profile equivalent to a fresh Proxifier profile:
// localhost goes direct and everything else goes direct via the Default rule.
func Default() *Profile {
	return &Profile{
		Version: CurrentVersion,
		Options: Options{
			Resolve: Resolve{
				AutoDetect:    true,
				ExclusionList: "%ComputerName%; localhost; *.local",
			},
			Encryption:              EncBasic,
			ConnectionLoopDetection: true,
			ResolveLoopDetection:    true,
			UDPMode:                 UDPBypass,
		},
		Proxies: []Proxy{},
		Chains:  []Chain{},
		Rules: []Rule{
			{Name: "Localhost", Enabled: true, Targets: "localhost; 127.0.0.1; %ComputerName%; ::1", Action: Action{Type: ActDirect}},
			{Name: "Default", Enabled: true, Action: Action{Type: ActDirect}},
		},
	}
}

// Clone returns a deep copy.
func (p *Profile) Clone() *Profile {
	b, _ := json.Marshal(p)
	var c Profile
	_ = json.Unmarshal(b, &c)
	return &c
}

func (p *Profile) ProxyByID(id int) *Proxy {
	for i := range p.Proxies {
		if p.Proxies[i].ID == id {
			return &p.Proxies[i]
		}
	}
	return nil
}

func (p *Profile) ChainByID(id int) *Chain {
	for i := range p.Chains {
		if p.Chains[i].ID == id {
			return &p.Chains[i]
		}
	}
	return nil
}

// NextID returns an unused proxy/chain identifier (they share a namespace,
// starting from 100 like Proxifier).
func (p *Profile) NextID() int {
	id := 100
	for _, x := range p.Proxies {
		if x.ID >= id {
			id = x.ID + 1
		}
	}
	for _, x := range p.Chains {
		if x.ID >= id {
			id = x.ID + 1
		}
	}
	return id
}

// Normalize fills in defaults and repairs structural problems so that the
// profile is always usable by the engine.
func (p *Profile) Normalize() {
	if p.Version == 0 {
		p.Version = CurrentVersion
	}
	if p.Proxies == nil {
		p.Proxies = []Proxy{}
	}
	if p.Chains == nil {
		p.Chains = []Chain{}
	}
	switch p.Options.UDPMode {
	case UDPBypass, UDPBlock443, UDPBlockAll:
	default:
		p.Options.UDPMode = UDPBypass
	}
	switch p.Options.Encryption {
	case EncDisabled, EncBasic, EncUser, EncMaster:
	default:
		p.Options.Encryption = EncBasic
	}
	for i := range p.Proxies {
		x := &p.Proxies[i]
		x.Type = strings.ToUpper(strings.TrimSpace(x.Type))
		if x.Type == "" {
			x.Type = SOCKS5
		}
		x.Address = strings.TrimSpace(x.Address)
		if x.ID == 0 {
			x.ID = p.NextID()
		}
	}
	for i := range p.Chains {
		c := &p.Chains[i]
		if c.ID == 0 {
			c.ID = p.NextID()
		}
		switch c.Type {
		case ChainSimple, ChainRedundancy, ChainLoadBalance:
		default:
			c.Type = ChainSimple
		}
		if c.TimeoutSec <= 0 {
			c.TimeoutSec = 30
		}
		if c.Proxies == nil {
			c.Proxies = []ChainItem{}
		}
	}
	// The last rule is always the Default rule: enabled, no filters.
	n := len(p.Rules)
	if n == 0 || p.Rules[n-1].Applications != "" || p.Rules[n-1].Targets != "" || p.Rules[n-1].Ports != "" {
		p.Rules = append(p.Rules, Rule{Name: "Default", Action: Action{Type: ActDirect}})
		n++
	}
	p.Rules[n-1].Enabled = true
	if p.Rules[n-1].Name == "" {
		p.Rules[n-1].Name = "Default"
	}
	for i := range p.Rules {
		switch p.Rules[i].Action.Type {
		case ActDirect, ActBlock, ActProxy, ActChain:
		default:
			p.Rules[i].Action = Action{Type: ActDirect}
		}
	}
}

// Validate reports the first problem that would make the profile unusable.
func (p *Profile) Validate() error {
	seen := map[int]bool{}
	for _, x := range p.Proxies {
		if x.Address == "" {
			return errors.New("proxy server address must not be empty")
		}
		if x.Port < 1 || x.Port > 65535 {
			return fmt.Errorf("proxy %s: port must be between 1 and 65535", x.Address)
		}
		switch x.Type {
		case SOCKS5, SOCKS4, HTTPS:
		case HTTP:
			if !p.Options.HTTPProxySupport {
				return fmt.Errorf("proxy %s: HTTP proxy servers support is not enabled", x.HostPort())
			}
		default:
			return fmt.Errorf("proxy %s: unknown protocol %q", x.HostPort(), x.Type)
		}
		if seen[x.ID] {
			return fmt.Errorf("duplicate proxy/chain id %d", x.ID)
		}
		seen[x.ID] = true
	}
	for _, c := range p.Chains {
		if seen[c.ID] {
			return fmt.Errorf("duplicate proxy/chain id %d", c.ID)
		}
		seen[c.ID] = true
		if strings.TrimSpace(c.Name) == "" {
			return errors.New("chain name must not be empty")
		}
		for _, it := range c.Proxies {
			if p.ProxyByID(it.ID) == nil {
				return fmt.Errorf("chain %q refers to unknown proxy id %d", c.Name, it.ID)
			}
		}
	}
	for _, r := range p.Rules {
		switch r.Action.Type {
		case ActProxy:
			if p.ProxyByID(r.Action.ID) == nil {
				return fmt.Errorf("rule %q refers to unknown proxy id %d", r.Name, r.Action.ID)
			}
		case ActChain:
			if p.ChainByID(r.Action.ID) == nil {
				return fmt.Errorf("rule %q refers to unknown chain id %d", r.Name, r.Action.ID)
			}
		}
	}
	return nil
}

// RulesUsing lists the names of rules whose action is the given proxy/chain.
func (p *Profile) RulesUsing(id int) []string {
	var out []string
	for _, r := range p.Rules {
		if (r.Action.Type == ActProxy || r.Action.Type == ActChain) && r.Action.ID == id {
			out = append(out, r.Name)
		}
	}
	return out
}

// ActionLabel renders a human readable action, e.g. "Proxy SOCKS5 1.2.3.4:1080".
func (p *Profile) ActionLabel(a Action) string {
	switch a.Type {
	case ActProxy:
		if x := p.ProxyByID(a.ID); x != nil {
			return "Proxy " + x.Type + " " + x.Display()
		}
	case ActChain:
		if c := p.ChainByID(a.ID); c != nil {
			return "Chain " + c.Name
		}
	}
	return a.Type
}

// ---- storage -------------------------------------------------------------

// Load reads a profile from a native JSON file or a Proxifier .ppx file.
func Load(path string, kr *Keyring) (*Profile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(b, kr)
}

// Parse auto-detects JSON vs. Proxifier XML.
func Parse(b []byte, kr *Keyring) (*Profile, error) {
	t := strings.TrimSpace(strings.TrimPrefix(string(b), string([]byte{0xEF, 0xBB, 0xBF})))
	if strings.HasPrefix(t, "<") {
		return ParsePPX([]byte(t))
	}
	var p Profile
	if err := json.Unmarshal([]byte(t), &p); err != nil {
		return nil, fmt.Errorf("invalid profile: %w", err)
	}
	p.Normalize()
	if err := kr.decryptAll(&p); err != nil {
		return &p, err
	}
	return &p, nil
}

// Marshal serializes the profile to JSON with passwords encrypted according
// to Options.Encryption.
func (p *Profile) Marshal(kr *Keyring) ([]byte, error) {
	c := p.Clone()
	if err := kr.encryptAll(c); err != nil {
		return nil, err
	}
	return json.MarshalIndent(c, "", "  ")
}

func (p *Profile) Save(path string, kr *Keyring) error {
	b, err := p.Marshal(kr)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

const Ext = ".shunt.json"

// List returns profile names found in dir.
func List(dir string) []string {
	ents, _ := os.ReadDir(dir)
	var out []string
	for _, e := range ents {
		if !e.IsDir() && strings.HasSuffix(e.Name(), Ext) {
			out = append(out, strings.TrimSuffix(e.Name(), Ext))
		}
	}
	sort.Strings(out)
	return out
}

// SafeName strips characters that are not valid in file names.
func SafeName(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Map(func(r rune) rune {
		if strings.ContainsRune(`<>:"/\|?*`, r) || r < 32 {
			return -1
		}
		return r
	}, s)
	s = strings.Trim(s, ". ")
	if len(s) > 80 {
		s = s[:80]
	}
	return s
}
