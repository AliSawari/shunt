// Command mkres writes cmd/shunt/rsrc_windows_amd64.syso: a COFF object with
// the application icon (16-256 px) and the application manifest, which the Go
// linker embeds into shunt.exe. No external resource compiler is needed.
//
//	go run ./tools/mkres
package main

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/png"
	"log"
	"os"
	"sort"

	"shunt/internal/brand"
)

const (
	rtIcon      = 3
	rtGroupIcon = 14
	rtManifest  = 24
	langEnUS    = 0x0409
)

type res struct {
	typ, id int
	data    []byte
}

// dib encodes an icon image as a 32-bit BITMAPINFOHEADER DIB with AND mask.
func dib(img *image.NRGBA) []byte {
	n := img.Bounds().Dx()
	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, struct {
		Size                          uint32
		W, H                          int32
		Planes, Bits                  uint16
		Compression, ImageSize        uint32
		XPPM, YPPM, ClrUsed, ClrImpor int32
	}{40, int32(n), int32(2 * n), 1, 32, 0, 0, 0, 0, 0, 0})
	for y := n - 1; y >= 0; y-- {
		for x := 0; x < n; x++ {
			c := img.NRGBAAt(x, y)
			b.Write([]byte{c.B, c.G, c.R, c.A})
		}
	}
	stride := ((n + 31) / 32) * 4
	for y := n - 1; y >= 0; y-- {
		row := make([]byte, stride)
		for x := 0; x < n; x++ {
			if img.NRGBAAt(x, y).A == 0 {
				row[x/8] |= 0x80 >> (x % 8)
			}
		}
		b.Write(row)
	}
	return b.Bytes()
}

func main() {
	manifest, err := os.ReadFile("cmd/shunt/shunt.manifest")
	if err != nil {
		log.Fatal(err)
	}
	var list []res
	var group bytes.Buffer
	sizes := []int{16, 20, 24, 32, 40, 48, 64, 256}
	binary.Write(&group, binary.LittleEndian, []uint16{0, 1, uint16(len(sizes))})
	for i, s := range sizes {
		img := brand.Logo(s)
		var data []byte
		if s >= 256 {
			var p bytes.Buffer
			png.Encode(&p, img)
			data = p.Bytes()
		} else {
			data = dib(img)
		}
		id := i + 1
		list = append(list, res{rtIcon, id, data})
		dim := byte(s)
		if s >= 256 {
			dim = 0
		}
		group.Write([]byte{dim, dim, 0, 0})
		binary.Write(&group, binary.LittleEndian, []uint16{1, 32})
		binary.Write(&group, binary.LittleEndian, uint32(len(data)))
		binary.Write(&group, binary.LittleEndian, uint16(id))
	}
	list = append(list, res{rtGroupIcon, 1, group.Bytes()}, res{rtManifest, 1, manifest})
	if err := os.WriteFile("cmd/shunt/rsrc_windows_amd64.syso", coff(list), 0o644); err != nil {
		log.Fatal(err)
	}
	log.Printf("wrote cmd/shunt/rsrc_windows_amd64.syso (%d resources)", len(list))
}

// coff lays out a .rsrc section: type -> id -> language directories, data
// entries, then the raw data. Data entry RVAs get ADDR32NB relocations.
func coff(list []res) []byte {
	sort.Slice(list, func(i, j int) bool {
		if list[i].typ != list[j].typ {
			return list[i].typ < list[j].typ
		}
		return list[i].id < list[j].id
	})
	types := map[int][]int{}
	var order []int
	for i, r := range list {
		if _, ok := types[r.typ]; !ok {
			order = append(order, r.typ)
		}
		types[r.typ] = append(types[r.typ], i)
	}
	dirSize := func(n int) int { return 16 + 8*n }
	// Offsets: root dir, then one dir per type, then one lang dir per resource.
	off := dirSize(len(order))
	typeDir := map[int]int{}
	for _, t := range order {
		typeDir[t] = off
		off += dirSize(len(types[t]))
	}
	langDir := make([]int, len(list))
	for i := range list {
		langDir[i] = off
		off += dirSize(1)
	}
	entry := make([]int, len(list))
	for i := range list {
		entry[i] = off
		off += 16
	}
	dataOff := make([]int, len(list))
	for i, r := range list {
		off = (off + 7) &^ 7
		dataOff[i] = off
		off += len(r.data)
	}
	sec := make([]byte, (off+7)&^7)
	le := binary.LittleEndian
	writeDir := func(at, n int) { le.PutUint16(sec[at+14:], uint16(n)) }
	writeEnt := func(at, k, id int, target uint32) {
		le.PutUint32(sec[at+16+8*k:], uint32(id))
		le.PutUint32(sec[at+16+8*k+4:], target)
	}
	writeDir(0, len(order))
	for k, t := range order {
		writeEnt(0, k, t, 0x80000000|uint32(typeDir[t]))
		writeDir(typeDir[t], len(types[t]))
		for j, i := range types[t] {
			writeEnt(typeDir[t], j, list[i].id, 0x80000000|uint32(langDir[i]))
		}
	}
	var relocs []uint32
	for i, r := range list {
		writeDir(langDir[i], 1)
		writeEnt(langDir[i], 0, langEnUS, uint32(entry[i]))
		le.PutUint32(sec[entry[i]:], uint32(dataOff[i]))
		le.PutUint32(sec[entry[i]+4:], uint32(len(r.data)))
		relocs = append(relocs, uint32(entry[i]))
		copy(sec[dataOff[i]:], r.data)
	}

	var b bytes.Buffer
	const hdr, shdr = 20, 40
	relocAt := hdr + shdr + len(sec)
	symAt := relocAt + 10*len(relocs)
	binary.Write(&b, le, struct {
		Machine, NSections       uint16
		Time, SymPtr, NSyms      uint32
		OptSize, Characteristics uint16
	}{0x8664, 1, 0, uint32(symAt), 1, 0, 0})
	name := [8]byte{'.', 'r', 's', 'r', 'c'}
	binary.Write(&b, le, struct {
		Name                                  [8]byte
		VSize, VAddr, RawSize, RawPtr, RelPtr uint32
		LinePtr                               uint32
		NReloc, NLines                        uint16
		Characteristics                       uint32
	}{name, 0, 0, uint32(len(sec)), hdr + shdr, uint32(relocAt), 0, uint16(len(relocs)), 0, 0x40000040})
	b.Write(sec)
	for _, r := range relocs {
		binary.Write(&b, le, r)         // VirtualAddress
		binary.Write(&b, le, uint32(0)) // symbol 0 (.rsrc)
		binary.Write(&b, le, uint16(3)) // IMAGE_REL_AMD64_ADDR32NB
	}
	binary.Write(&b, le, struct {
		Name    [8]byte
		Value   uint32
		Section int16
		Type    uint16
		Class   uint8
		NAux    uint8
	}{name, 0, 1, 0, 3, 0})
	binary.Write(&b, le, uint32(4)) // empty string table
	return b.Bytes()
}
