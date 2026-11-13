package main

import (
	"testing"
	"time"

	"github.com/lxn/walk"

	"shunt/internal/core"
)

func conn(id int64, app, target string, age time.Duration, sent, recv int64) *core.ConnInfo {
	c := &core.ConnInfo{ID: id, App: app, PID: uint32(id), Target: target, Rule: "Default", Via: "directly", Start: time.Now().Add(-age)}
	c.Sent.Store(sent)
	c.Recv.Store(recv)
	return c
}

func order(m *connModel) []int64 {
	var ids []int64
	for _, r := range m.rows {
		ids = append(ids, r.ID)
	}
	return ids
}

func TestConnModelSort(t *testing.T) {
	m := &connModel{rows: []*core.ConnInfo{
		conn(1, "firefox.exe", "b.example.com:443", 30*time.Second, 500, 10),
		conn(2, "Chrome.exe", "c.example.com:443", 5*time.Second, 100, 9000),
		conn(3, "curl.exe", "a.example.com:80", 90*time.Second, 2000, 50),
	}}
	cases := []struct {
		col   int
		ord   walk.SortOrder
		want  []int64
		label string
	}{
		{0, walk.SortAscending, []int64{2, 3, 1}, "application asc (case-insensitive)"},
		{0, walk.SortDescending, []int64{1, 3, 2}, "application desc"},
		{1, walk.SortAscending, []int64{3, 1, 2}, "target asc"},
		{1, walk.SortDescending, []int64{2, 1, 3}, "target desc"},
		{2, walk.SortAscending, []int64{2, 1, 3}, "time asc (newest first)"},
		{2, walk.SortDescending, []int64{3, 1, 2}, "time desc (oldest first)"},
		{4, walk.SortAscending, []int64{2, 1, 3}, "sent asc"},
		{5, walk.SortDescending, []int64{2, 3, 1}, "received desc"},
	}
	for _, c := range cases {
		m.Sort(c.col, c.ord)
		got := order(m)
		for i := range got {
			if got[i] != c.want[i] {
				t.Fatalf("%s: got %v, want %v", c.label, got, c.want)
			}
		}
		if m.SortedColumn() != c.col || m.SortOrder() != c.ord {
			t.Fatalf("%s: sorter state not recorded", c.label)
		}
	}
}
