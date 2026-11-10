// Package procinfo maps network sockets to the processes that own them.
package procinfo

import (
	"net/netip"
	"sync"
	"time"
)

// Info describes the process behind a connection.
type Info struct {
	PID  uint32 `json:"pid"`
	Name string `json:"name"` // executable file name
	Path string `json:"path"` // full image path when accessible
	// OtherUser is set when the process belongs to a different interactive user.
	OtherUser bool `json:"otherUser,omitempty"`
	// Service is set for system services and other non-interactive processes.
	Service bool `json:"service,omitempty"`
}

type cacheEntry struct {
	info Info
	at   time.Time
}

var (
	cacheMu sync.Mutex
	cache   = map[uint32]cacheEntry{}
)

// ByPID returns (cached) information about a process.
func ByPID(pid uint32) Info {
	cacheMu.Lock()
	if e, ok := cache[pid]; ok && time.Since(e.at) < 20*time.Second {
		cacheMu.Unlock()
		return e.info
	}
	cacheMu.Unlock()
	info := queryPID(pid)
	cacheMu.Lock()
	if len(cache) > 4096 {
		cache = map[uint32]cacheEntry{}
	}
	cache[pid] = cacheEntry{info, time.Now()}
	cacheMu.Unlock()
	return info
}

// Lookup finds the process owning the socket with the given local endpoint.
// network is "tcp" or "udp". remote may be the zero value.
func Lookup(network string, local, remote netip.AddrPort) (Info, bool) {
	pid, ok := findOwner(network, local, remote)
	if !ok {
		return Info{}, false
	}
	return ByPID(pid), true
}

// ListenerPID returns the process listening on the given local TCP port.
func ListenerPID(port uint16) (uint32, bool) { return findListener(port) }
