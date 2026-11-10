package procinfo

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	iphlpapi            = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtTCPTable  = iphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtUDPTable  = iphlpapi.NewProc("GetExtendedUdpTable")
	tcpTableOwnerPIDAll = uintptr(5)
	udpTableOwnerPID    = uintptr(1)
)

const tcpStateListen = 2

func table(proc *windows.LazyProc, family, class uintptr) []byte {
	size := uint32(64 << 10)
	for i := 0; i < 5; i++ {
		buf := make([]byte, size)
		r, _, _ := proc.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, family, class, 0)
		if r == 0 {
			return buf
		}
		if r != uintptr(windows.ERROR_INSUFFICIENT_BUFFER) {
			return nil
		}
		size += 16 << 10
	}
	return nil
}

func port(b []byte) uint16 { return binary.BigEndian.Uint16(b[:2]) }

type tcpRow struct {
	state        uint32
	local        netip.AddrPort
	remote       netip.AddrPort
	pid          uint32
}

func tcpRows() []tcpRow {
	var rows []tcpRow
	if b := table(procGetExtTCPTable, windows.AF_INET, tcpTableOwnerPIDAll); len(b) >= 4 {
		n := int(binary.LittleEndian.Uint32(b))
		for i, off := 0, 4; i < n && off+24 <= len(b); i, off = i+1, off+24 {
			r := b[off:]
			rows = append(rows, tcpRow{
				state:  binary.LittleEndian.Uint32(r),
				local:  netip.AddrPortFrom(netip.AddrFrom4([4]byte(r[4:8])), port(r[8:])),
				remote: netip.AddrPortFrom(netip.AddrFrom4([4]byte(r[12:16])), port(r[16:])),
				pid:    binary.LittleEndian.Uint32(r[20:]),
			})
		}
	}
	if b := table(procGetExtTCPTable, windows.AF_INET6, tcpTableOwnerPIDAll); len(b) >= 4 {
		n := int(binary.LittleEndian.Uint32(b))
		for i, off := 0, 4; i < n && off+56 <= len(b); i, off = i+1, off+56 {
			r := b[off:]
			rows = append(rows, tcpRow{
				local:  netip.AddrPortFrom(netip.AddrFrom16([16]byte(r[0:16])).Unmap(), port(r[20:])),
				remote: netip.AddrPortFrom(netip.AddrFrom16([16]byte(r[24:40])).Unmap(), port(r[44:])),
				state:  binary.LittleEndian.Uint32(r[48:]),
				pid:    binary.LittleEndian.Uint32(r[52:]),
			})
		}
	}
	return rows
}

func findOwner(network string, local, remote netip.AddrPort) (uint32, bool) {
	if network == "udp" {
		if b := table(procGetExtUDPTable, windows.AF_INET, udpTableOwnerPID); len(b) >= 4 {
			n := int(binary.LittleEndian.Uint32(b))
			for i, off := 0, 4; i < n && off+12 <= len(b); i, off = i+1, off+12 {
				if port(b[off+4:]) == local.Port() {
					return binary.LittleEndian.Uint32(b[off+8:]), true
				}
			}
		}
		if b := table(procGetExtUDPTable, windows.AF_INET6, udpTableOwnerPID); len(b) >= 4 {
			n := int(binary.LittleEndian.Uint32(b))
			for i, off := 0, 4; i < n && off+28 <= len(b); i, off = i+1, off+28 {
				if port(b[off+20:]) == local.Port() {
					return binary.LittleEndian.Uint32(b[off+24:]), true
				}
			}
		}
		return 0, false
	}
	var fallback uint32
	found := false
	for _, r := range tcpRows() {
		if r.state == tcpStateListen || r.local.Port() != local.Port() {
			continue
		}
		// Best match: same remote endpoint too.
		if remote.IsValid() && r.remote.Port() == remote.Port() && r.remote.Addr() == remote.Addr().Unmap() {
			return r.pid, true
		}
		if !found {
			fallback, found = r.pid, true
		}
	}
	return fallback, found
}

func findListener(p uint16) (uint32, bool) {
	for _, r := range tcpRows() {
		if r.state == tcpStateListen && r.local.Port() == p {
			return r.pid, true
		}
	}
	return 0, false
}

var (
	selfOnce    sync.Once
	selfSID     string
	selfSystem  bool
	selfSession uint32
)

func initSelf() {
	tok := windows.GetCurrentProcessToken()
	if u, err := tok.GetTokenUser(); err == nil {
		selfSID = u.User.Sid.String()
		selfSystem = u.User.Sid.IsWellKnown(windows.WinLocalSystemSid)
	}
	windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &selfSession)
}

func queryPID(pid uint32) Info {
	selfOnce.Do(initSelf)
	info := Info{PID: pid}
	switch pid {
	case 0:
		info.Name, info.Service = "Idle", true
		return info
	case 4:
		info.Name, info.Service = "System", true
		return info
	}
	var session uint32
	if err := windows.ProcessIdToSessionId(pid, &session); err == nil && session == 0 {
		info.Service = true
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		info.Name = "pid:" + itoa(pid)
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			info.Service = true
		}
		return info
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, 1024)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err == nil {
		info.Path = syscall.UTF16ToString(buf[:n])
		info.Name = filepath.Base(info.Path)
	} else {
		info.Name = "pid:" + itoa(pid)
	}
	var tok windows.Token
	if err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &tok); err == nil {
		defer tok.Close()
		if u, err := tok.GetTokenUser(); err == nil {
			sid := u.User.Sid
			if sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinLocalServiceSid) || sid.IsWellKnown(windows.WinNetworkServiceSid) {
				info.Service = true
			} else if !selfSystem && selfSID != "" && sid.String() != selfSID {
				info.OtherUser = true
			}
		}
	} else if !info.Service {
		// Cannot inspect the token of a process in an interactive session:
		// it belongs to someone else.
		info.OtherUser = !selfSystem
	}
	return info
}

func itoa(v uint32) string {
	if v == 0 {
		return "0"
	}
	var b [10]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

// Kill terminates a process.
func Kill(pid uint32) error {
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, pid)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	return windows.TerminateProcess(h, 1)
}

// Running lists the distinct executable names of running processes.
func Running() []string {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(snap)
	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	seen := map[string]bool{}
	var out []string
	for err = windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		name := windows.UTF16ToString(e.ExeFile[:])
		k := strings.ToLower(name)
		if name == "" || seen[k] || e.ProcessID == 0 {
			continue
		}
		seen[k] = true
		out = append(out, name)
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i]) < strings.ToLower(out[j]) })
	return out
}
