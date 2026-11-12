// Package brand draws Shunt's logo and toolbar icons in code, so the program
// needs no image files. Shapes are rendered with 4x4 supersampling.
package brand

import (
	"image"
	"image/color"
	"math"
)

const (
	Author  = "Ali Sawari"
	RepoURL = "https://github.com/AliSawari/shunt"
)

type shape func(x, y float64) bool

type layer struct {
	in  shape
	col func(x, y float64) color.NRGBA
}

func solid(c color.NRGBA) func(x, y float64) color.NRGBA {
	return func(float64, float64) color.NRGBA { return c }
}

func hex(v uint32) color.NRGBA {
	return color.NRGBA{uint8(v >> 16), uint8(v >> 8), uint8(v), 255}
}

var white = hex(0xFFFFFF)

func render(size int, layers []layer) *image.NRGBA {
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	const ss = 4
	for py := 0; py < size; py++ {
		for px := 0; px < size; px++ {
			var r, g, b, a float64
			for sy := 0; sy < ss; sy++ {
				for sx := 0; sx < ss; sx++ {
					x := (float64(px) + (float64(sx)+0.5)/ss) / float64(size)
					y := (float64(py) + (float64(sy)+0.5)/ss) / float64(size)
					var c color.NRGBA
					for _, l := range layers {
						if l.in(x, y) {
							c = l.col(x, y)
						}
					}
					fa := float64(c.A) / 255
					r += float64(c.R) * fa
					g += float64(c.G) * fa
					b += float64(c.B) * fa
					a += fa
				}
			}
			if a == 0 {
				continue
			}
			img.SetNRGBA(px, py, color.NRGBA{uint8(r / a), uint8(g / a), uint8(b / a), uint8(a / (ss * ss) * 255)})
		}
	}
	return img
}

func circle(cx, cy, r float64) shape {
	return func(x, y float64) bool { return (x-cx)*(x-cx)+(y-cy)*(y-cy) <= r*r }
}

func ring(cx, cy, r, w float64) shape {
	return func(x, y float64) bool {
		d := math.Hypot(x-cx, y-cy)
		return d <= r && d >= r-w
	}
}

func rrect(x0, y0, x1, y1, rad float64) shape {
	return func(x, y float64) bool {
		if x < x0 || x > x1 || y < y0 || y > y1 {
			return false
		}
		dx := math.Max(math.Max(x0+rad-x, x-(x1-rad)), 0)
		dy := math.Max(math.Max(y0+rad-y, y-(y1-rad)), 0)
		return dx*dx+dy*dy <= rad*rad
	}
}

func capsule(ax, ay, bx, by, w float64) shape {
	return func(x, y float64) bool {
		dx, dy := bx-ax, by-ay
		t := math.Max(0, math.Min(1, ((x-ax)*dx+(y-ay)*dy)/(dx*dx+dy*dy)))
		ex, ey := x-ax-t*dx, y-ay-t*dy
		return ex*ex+ey*ey <= w*w
	}
}

func triangle(ax, ay, bx, by, cx, cy float64) shape {
	side := func(px, py, qx, qy, x, y float64) float64 { return (qx-px)*(y-py) - (qy-py)*(x-px) }
	return func(x, y float64) bool {
		d1, d2, d3 := side(ax, ay, bx, by, x, y), side(bx, by, cx, cy, x, y), side(cx, cy, ax, ay, x, y)
		neg := d1 < 0 || d2 < 0 || d3 < 0
		pos := d1 > 0 || d2 > 0 || d3 > 0
		return !(neg && pos)
	}
}

func union(s ...shape) shape {
	return func(x, y float64) bool {
		for _, f := range s {
			if f(x, y) {
				return true
			}
		}
		return false
	}
}

// Logo draws the Shunt mark: one track splitting into two, on an
// indigo-to-cyan rounded square.
func Logo(size int) *image.NRGBA {
	grad := func(x, y float64) color.NRGBA {
		t := (x + y) / 2
		a, b := hex(0x4F46E5), hex(0x06B6D4)
		mix := func(p, q uint8) uint8 { return uint8(float64(p)*(1-t) + float64(q)*t) }
		return color.NRGBA{mix(a.R, b.R), mix(a.G, b.G), mix(a.B, b.B), 255}
	}
	const w = 0.065
	mark := union(
		capsule(0.20, 0.50, 0.46, 0.50, w),
		capsule(0.46, 0.50, 0.74, 0.30, w),
		capsule(0.46, 0.50, 0.74, 0.70, w),
		circle(0.20, 0.50, 0.095),
		circle(0.78, 0.28, 0.095),
		circle(0.78, 0.72, 0.095),
	)
	return render(size, []layer{
		{rrect(0.03, 0.03, 0.97, 0.97, 0.22), grad},
		{mark, solid(white)},
	})
}

// Start is a green play button.
func Start(size int) *image.NRGBA {
	return render(size, []layer{
		{circle(0.5, 0.5, 0.47), solid(hex(0x16A34A))},
		{triangle(0.39, 0.28, 0.39, 0.72, 0.75, 0.5), solid(white)},
	})
}

// Stop is a red stop button.
func Stop(size int) *image.NRGBA {
	return render(size, []layer{
		{circle(0.5, 0.5, 0.47), solid(hex(0xDC2626))},
		{rrect(0.32, 0.32, 0.68, 0.68, 0.06), solid(white)},
	})
}

// Servers is the proxy servers icon.
func Servers(size int) *image.NRGBA {
	blue := solid(hex(0x2563EB))
	return render(size, []layer{
		{rrect(0.08, 0.12, 0.92, 0.45, 0.09), blue},
		{rrect(0.08, 0.55, 0.92, 0.88, 0.09), blue},
		{union(circle(0.23, 0.285, 0.06), circle(0.23, 0.715, 0.06),
			capsule(0.42, 0.285, 0.78, 0.285, 0.04), capsule(0.42, 0.715, 0.78, 0.715, 0.04)), solid(white)},
	})
}

// Rules is the proxification rules icon (an ordered list).
func Rules(size int) *image.NRGBA {
	var marks []shape
	for _, y := range []float64{0.30, 0.50, 0.70} {
		marks = append(marks, circle(0.29, y, 0.06), capsule(0.44, y, 0.74, y, 0.04))
	}
	return render(size, []layer{
		{rrect(0.10, 0.08, 0.90, 0.92, 0.12), solid(hex(0x7C3AED))},
		{union(marks...), solid(white)},
	})
}

// Globe is the name resolution icon.
func Globe(size int) *image.NRGBA {
	meridian := func(x, y float64) bool {
		e := math.Pow((x-0.5)/0.19, 2) + math.Pow((y-0.5)/0.40, 2)
		return e <= 1 && e >= 0.62
	}
	inside := circle(0.5, 0.5, 0.40)
	lines := func(x, y float64) bool {
		if !inside(x, y) {
			return false
		}
		return meridian(x, y) || math.Abs(y-0.5) < 0.032 || math.Abs(y-0.31) < 0.028 || math.Abs(y-0.69) < 0.028 || math.Abs(x-0.5) < 0.03
	}
	return render(size, []layer{
		{circle(0.5, 0.5, 0.47), solid(hex(0x0D9488))},
		{lines, solid(white)},
		{ring(0.5, 0.5, 0.42, 0.05), solid(white)},
	})
}

// Gear is the advanced settings icon.
func Gear(size int) *image.NRGBA {
	const teeth = 8
	gear := func(x, y float64) bool {
		dx, dy := x-0.5, y-0.5
		r := math.Hypot(dx, dy)
		if r <= 0.33 {
			return true
		}
		if r > 0.47 {
			return false
		}
		a := math.Atan2(dy, dx)
		step := 2 * math.Pi / teeth
		d := math.Abs(math.Remainder(a, step))
		return d*r < 0.075
	}
	return render(size, []layer{
		{gear, solid(hex(0x475569))},
		{circle(0.5, 0.5, 0.14), solid(white)},
	})
}

// Check is the proxy checker icon (a check mark in a circle).
func Check(size int) *image.NRGBA {
	return render(size, []layer{
		{circle(0.5, 0.5, 0.47), solid(hex(0x0284C7))},
		{union(capsule(0.28, 0.52, 0.44, 0.68, 0.055), capsule(0.44, 0.68, 0.74, 0.34, 0.055)), solid(white)},
	})
}

// Info is the about icon.
func Info(size int) *image.NRGBA {
	return render(size, []layer{
		{circle(0.5, 0.5, 0.47), solid(hex(0x64748B))},
		{union(circle(0.5, 0.29, 0.065), capsule(0.5, 0.45, 0.5, 0.74, 0.055)), solid(white)},
	})
}
