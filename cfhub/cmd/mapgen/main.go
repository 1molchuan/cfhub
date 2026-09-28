// mapgen turns the province-level China map from DataV.GeoAtlas (Alibaba Cloud, data from AutoNavi)
// into the SVG path data cfhub renders its volunteer map with (geo/china.json):
//
//	curl -o china.json https://geo.datav.aliyun.com/areas_v3/bound/100000_full.json
//	go run ./cmd/mapgen -in china.json -out geo/china.json
//
// The map is complete: every province including Taiwan, Hong Kong and Macao, with the South China
// Sea islands and the nine-dash line in the usual inset at the bottom right. Coordinates are
// projected (Albers equal-area conic, parallels 25N/47N, central meridian 105E) and simplified with
// Douglas-Peucker; no polygon is dropped, however small, so outlying islands stay on the map.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
)

const (
	width     = 1000.0 // main map width in SVG units
	tolerance = 0.45   // simplification tolerance in SVG units
	southCut  = 17.5   // polygons entirely south of this latitude go to the inset only
)

// Inset: the South China Sea, drawn at its own scale inside a box at the bottom right.
var insetLon, insetLat = [2]float64{106, 123}, [2]float64{3, 24.5}

type geoJSON struct {
	Features []struct {
		Properties struct {
			Adcode   any       `json:"adcode"`
			Name     string    `json:"name"`
			Centroid []float64 `json:"centroid"`
			Center   []float64 `json:"center"`
		} `json:"properties"`
		Geometry struct {
			Type        string          `json:"type"`
			Coordinates json.RawMessage `json:"coordinates"`
		} `json:"geometry"`
	} `json:"features"`
}

type Province struct {
	Adcode string  `json:"adcode"`
	Name   string  `json:"name"`
	D      string  `json:"d"`
	X      float64 `json:"x"` // label position
	Y      float64 `json:"y"`
}

type Inset struct {
	X, Y, W, H float64
	Paths      map[string]string `json:"paths"` // adcode -> d, clipped to the box when drawn
	NineDash   string            `json:"nine_dash"`
}

type Out struct {
	Source    string     `json:"source"`
	Width     float64    `json:"width"`
	Height    float64    `json:"height"`
	Provinces []Province `json:"provinces"`
	Inset     Inset      `json:"inset"`
}

type pt struct{ x, y float64 }

// Albers equal-area conic.
func albers(lon, lat float64) pt {
	rad := math.Pi / 180
	p1, p2, l0 := 25*rad, 47*rad, 105*rad
	n := (math.Sin(p1) + math.Sin(p2)) / 2
	c := math.Cos(p1)*math.Cos(p1) + 2*n*math.Sin(p1)
	rho := math.Sqrt(c-2*n*math.Sin(lat*rad)) / n
	theta := n * (lon*rad - l0)
	return pt{rho * math.Sin(theta), -rho * math.Cos(theta)} // y grows northwards here
}

type ring []pt // projected, unscaled

func polygons(kind string, raw json.RawMessage) ([][][][2]float64, error) {
	switch kind {
	case "Polygon":
		var p [][][2]float64
		err := json.Unmarshal(raw, &p)
		return [][][][2]float64{p}, err
	case "MultiPolygon":
		var mp [][][][2]float64
		err := json.Unmarshal(raw, &mp)
		return mp, err
	}
	return nil, fmt.Errorf("unsupported geometry %s", kind)
}

func simplify(points []pt, tol float64) []pt {
	if len(points) < 4 {
		return points
	}
	keep := make([]bool, len(points))
	keep[0], keep[len(points)-1] = true, true
	var rec func(a, b int)
	rec = func(a, b int) {
		maxD, idx := 0.0, -1
		ax, ay, bx, by := points[a].x, points[a].y, points[b].x, points[b].y
		dx, dy := bx-ax, by-ay
		l := math.Hypot(dx, dy)
		for i := a + 1; i < b; i++ {
			var d float64
			if l == 0 {
				d = math.Hypot(points[i].x-ax, points[i].y-ay)
			} else {
				d = math.Abs(dy*points[i].x-dx*points[i].y+bx*ay-by*ax) / l
			}
			if d > maxD {
				maxD, idx = d, i
			}
		}
		if maxD > tol && idx > 0 {
			keep[idx] = true
			rec(a, idx)
			rec(idx, b)
		}
	}
	rec(0, len(points)-1)
	var out []pt
	for i, k := range keep {
		if k {
			out = append(out, points[i])
		}
	}
	if len(out) < 4 { // a tiny island: keep its outline rather than lose it
		return points
	}
	return out
}

func num(v float64) string {
	s := strconv.FormatFloat(math.Round(v*10)/10, 'f', -1, 64)
	if s == "-0" {
		return "0"
	}
	return s
}

// pathD writes rings (already in SVG units) as one path with relative moves to keep it short.
func pathD(rings [][]pt) string {
	var b strings.Builder
	for _, r := range rings {
		if len(r) < 3 {
			continue
		}
		fmt.Fprintf(&b, "M%s %s", num(r[0].x), num(r[0].y))
		px, py := math.Round(r[0].x*10), math.Round(r[0].y*10)
		for _, p := range r[1:] {
			x, y := math.Round(p.x*10), math.Round(p.y*10)
			if x == px && y == py {
				continue
			}
			fmt.Fprintf(&b, "l%s %s", num((x-px)/10), num((y-py)/10))
			px, py = x, y
		}
		b.WriteString("z")
	}
	return b.String()
}

type feature struct {
	adcode, name string
	label        [2]float64
	rings        []ring // outer and inner rings of all polygons, projected
	south        []bool // per ring: entirely south of southCut
	lonlat       [][][2]float64
}

func main() {
	in := flag.String("in", "", "DataV GeoJSON (100000_full.json)")
	out := flag.String("out", "geo/china.json", "output")
	flag.Parse()
	raw, err := os.ReadFile(*in)
	check(err)
	var g geoJSON
	check(json.Unmarshal(raw, &g))

	var feats []feature
	for _, f := range g.Features {
		mp, err := polygons(f.Geometry.Type, f.Geometry.Coordinates)
		check(err)
		ft := feature{adcode: fmt.Sprint(f.Properties.Adcode), name: f.Properties.Name}
		if c := f.Properties.Centroid; len(c) == 2 {
			ft.label = [2]float64{c[0], c[1]}
		} else if c := f.Properties.Center; len(c) == 2 {
			ft.label = [2]float64{c[0], c[1]}
		}
		for _, poly := range mp {
			for _, r := range poly {
				var pr ring
				south := true
				for _, c := range r {
					pr = append(pr, albers(c[0], c[1]))
					south = south && c[1] < southCut
				}
				ft.rings = append(ft.rings, pr)
				ft.south = append(ft.south, south)
				ft.lonlat = append(ft.lonlat, r)
			}
		}
		feats = append(feats, ft)
	}

	// Main map: every ring north of the cut, and never the nine-dash line.
	minX, minY, maxX, maxY := math.Inf(1), math.Inf(1), math.Inf(-1), math.Inf(-1)
	for _, f := range feats {
		if f.adcode == "100000_JD" {
			continue
		}
		for i, r := range f.rings {
			if f.south[i] {
				continue
			}
			for _, p := range r {
				minX, maxX = math.Min(minX, p.x), math.Max(maxX, p.x)
				minY, maxY = math.Min(minY, p.y), math.Max(maxY, p.y)
			}
		}
	}
	margin := 10.0
	s := (width - 2*margin) / (maxX - minX)
	height := (maxY-minY)*s + 2*margin
	toMain := func(p pt) pt { return pt{(p.x-minX)*s + margin, (maxY-p.y)*s + margin} }

	// Inset box: the projected extent of the South China Sea window, scaled into the bottom right.
	iminX, iminY, imaxX, imaxY := math.Inf(1), math.Inf(1), math.Inf(-1), math.Inf(-1)
	for lon := insetLon[0]; lon <= insetLon[1]; lon += 0.5 {
		for _, lat := range []float64{insetLat[0], insetLat[1]} {
			p := albers(lon, lat)
			iminX, imaxX = math.Min(iminX, p.x), math.Max(imaxX, p.x)
			iminY, imaxY = math.Min(iminY, p.y), math.Max(imaxY, p.y)
		}
	}
	for lat := insetLat[0]; lat <= insetLat[1]; lat += 0.5 {
		for _, lon := range []float64{insetLon[0], insetLon[1]} {
			p := albers(lon, lat)
			iminX, imaxX = math.Min(iminX, p.x), math.Max(imaxX, p.x)
			iminY, imaxY = math.Min(iminY, p.y), math.Max(imaxY, p.y)
		}
	}
	ih := height * 0.24
	is := ih / (imaxY - iminY)
	iw := (imaxX - iminX) * is
	ix, iy := width-margin-iw, height-margin-ih
	// Keep the inset clear of land (Taiwan and the Fujian coast sit above that corner): move it below
	// the lowest main-map point in its columns, growing the canvas if needed.
	landBottom := 0.0
	for _, f := range feats {
		if f.adcode == "100000_JD" {
			continue
		}
		for i, r := range f.rings {
			if f.south[i] {
				continue
			}
			for _, p := range r {
				if q := toMain(p); q.x >= ix-6 && q.x <= ix+iw+6 {
					landBottom = math.Max(landBottom, q.y)
				}
			}
		}
	}
	iy = math.Max(iy, landBottom+14)
	height = math.Max(height, iy+ih+margin)
	toInset := func(p pt) pt { return pt{(p.x-iminX)*is + ix, (imaxY-p.y)*is + iy} }

	o := Out{
		Source: "DataV.GeoAtlas (Alibaba Cloud; data from AutoNavi), https://datav.aliyun.com/portal/school/atlas/area_selector",
		Width:  width, Height: math.Round(height),
		Inset: Inset{X: num2(ix), Y: num2(iy), W: num2(iw), H: num2(ih), Paths: map[string]string{}},
	}
	inInset := func(ll [][2]float64) bool {
		for _, c := range ll {
			if c[0] >= insetLon[0]-1 && c[0] <= insetLon[1]+1 && c[1] >= insetLat[0]-1 && c[1] <= insetLat[1]+1 {
				return true
			}
		}
		return false
	}
	for _, f := range feats {
		var main, inset [][]pt
		for i, r := range f.rings {
			if f.adcode != "100000_JD" && !f.south[i] {
				var pr []pt
				for _, p := range r {
					pr = append(pr, toMain(p))
				}
				main = append(main, simplify(pr, tolerance))
			}
			if inInset(f.lonlat[i]) {
				var pr []pt
				for _, p := range r {
					pr = append(pr, toInset(p))
				}
				inset = append(inset, simplify(pr, tolerance))
			}
		}
		if f.adcode == "100000_JD" {
			o.Inset.NineDash = pathD(inset)
			continue
		}
		if len(inset) > 0 {
			o.Inset.Paths[f.adcode] = pathD(inset)
		}
		l := toMain(albers(f.label[0], f.label[1]))
		o.Provinces = append(o.Provinces, Province{Adcode: f.adcode, Name: f.name, D: pathD(main), X: num2(l.x), Y: num2(l.y)})
	}
	body, err := json.Marshal(o)
	check(err)
	check(os.WriteFile(*out, body, 0o644))
	fmt.Printf("%s: %d provinces, %d bytes, %gx%g, inset %d paths\n", *out, len(o.Provinces), len(body), o.Width, o.Height, len(o.Inset.Paths))
}

func num2(v float64) float64 { return math.Round(v*10) / 10 }

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "mapgen:", err)
		os.Exit(1)
	}
}
