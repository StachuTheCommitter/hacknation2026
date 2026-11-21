// Package netx: parsowanie celów (IP, CIDR, zakresy, domeny), arytmetyka zakresów IPv4,
// specyfikacje portów i kontrola zakresu (scope). Bez zależności od bazy – w pełni testowalny.
package netx

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Range to domknięty zakres adresów IPv4 zapisany jako liczby.
type Range struct {
	Start uint32 `json:"s"`
	End   uint32 `json:"e"`
}

func (r Range) Size() uint64 { return uint64(r.End) - uint64(r.Start) + 1 }

func (r Range) String() string {
	if r.Start == r.End {
		return U32ToAddr(r.Start).String()
	}
	return U32ToAddr(r.Start).String() + "-" + U32ToAddr(r.End).String()
}

func AddrToU32(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func U32ToAddr(v uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// PrefixRange zamienia prefiks IPv4 na zakres.
func PrefixRange(p netip.Prefix) Range {
	p = p.Masked()
	start := AddrToU32(p.Addr())
	bits := 32 - p.Bits()
	var end uint32
	if bits == 32 {
		end = 0xFFFFFFFF
	} else {
		end = start | (uint32(1)<<bits - 1)
	}
	return Range{start, end}
}

// Target to znormalizowany cel.
type Target struct {
	Kind   string  // ip | cidr | range | domain
	Value  string  // postać kanoniczna
	Ranges []Range // dla IPv4
	IPv6   string  // pojedynczy adres IPv6
}

var domainRe = regexp.MustCompile(`^(?i)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.?$`)

// MaxTargetBits – największy dozwolony pojedynczy cel bez potwierdzenia (/16).
const MaxTargetBits = 16

// ParseTarget rozpoznaje i normalizuje jeden cel.
func ParseTarget(s string) (Target, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Target{}, errors.New("pusty cel")
	}
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return Target{}, fmt.Errorf("niepoprawny CIDR %q", s)
		}
		if !p.Addr().Is4() {
			return Target{}, errors.New("zakresy IPv6 nie są obsługiwane – podaj pojedyncze adresy")
		}
		p = p.Masked()
		if p.Bits() < MaxTargetBits {
			return Target{}, fmt.Errorf("zakres %s jest większy niż /%d", p, MaxTargetBits)
		}
		return Target{Kind: "cidr", Value: p.String(), Ranges: []Range{PrefixRange(p)}}, nil
	}
	if i := strings.Index(s, "-"); i > 0 && strings.Count(s, ".") >= 3 {
		a, err1 := netip.ParseAddr(strings.TrimSpace(s[:i]))
		rest := strings.TrimSpace(s[i+1:])
		var b netip.Addr
		var err2 error
		if !strings.Contains(rest, ".") && err1 == nil { // 10.0.0.1-50
			n, err := strconv.Atoi(rest)
			if err != nil || n > 255 {
				return Target{}, fmt.Errorf("niepoprawny zakres %q", s)
			}
			o := a.As4()
			o[3] = byte(n)
			b = netip.AddrFrom4(o)
		} else {
			b, err2 = netip.ParseAddr(rest)
		}
		if err1 != nil || err2 != nil || !a.Is4() || !b.Is4() {
			return Target{}, fmt.Errorf("niepoprawny zakres %q", s)
		}
		r := Range{AddrToU32(a), AddrToU32(b)}
		if r.End < r.Start {
			return Target{}, fmt.Errorf("odwrócony zakres %q", s)
		}
		if r.Size() > 1<<(32-MaxTargetBits) {
			return Target{}, fmt.Errorf("zakres %s jest większy niż /%d", s, MaxTargetBits)
		}
		return Target{Kind: "range", Value: r.String(), Ranges: []Range{r}}, nil
	}
	if a, err := netip.ParseAddr(s); err == nil {
		if a.Is4() || a.Is4In6() {
			a = a.Unmap()
			v := AddrToU32(a)
			return Target{Kind: "ip", Value: a.String(), Ranges: []Range{{v, v}}}, nil
		}
		return Target{Kind: "ip", Value: a.String(), IPv6: a.String()}, nil
	}
	if strings.Trim(s, "0123456789.") == "" {
		return Target{}, fmt.Errorf("niepoprawny adres IP %q", s)
	}
	if domainRe.MatchString(s) && strings.Contains(s, ".") {
		return Target{Kind: "domain", Value: strings.ToLower(strings.TrimSuffix(s, "."))}, nil
	}
	return Target{}, fmt.Errorf("nie rozpoznano celu %q (oczekiwano IP, CIDR, zakresu lub domeny)", s)
}

// SplitTargets dzieli tekst (linie, przecinki, spacje) na wartości.
func SplitTargets(text string) []string {
	f := strings.FieldsFunc(text, func(r rune) bool { return r == '\n' || r == '\r' || r == ',' || r == ';' || r == ' ' || r == '\t' })
	out := f[:0]
	for _, s := range f {
		s = strings.TrimSpace(s)
		if s != "" && !strings.HasPrefix(s, "#") {
			out = append(out, s)
		}
	}
	return out
}

// Merge sortuje i scala nakładające się lub sąsiednie zakresy.
func Merge(rs []Range) []Range {
	if len(rs) == 0 {
		return nil
	}
	c := append([]Range(nil), rs...)
	sort.Slice(c, func(i, j int) bool { return c[i].Start < c[j].Start })
	out := []Range{c[0]}
	for _, r := range c[1:] {
		last := &out[len(out)-1]
		if uint64(r.Start) <= uint64(last.End)+1 {
			if r.End > last.End {
				last.End = r.End
			}
			continue
		}
		out = append(out, r)
	}
	return out
}

// Subtract odejmuje zakresy b od a (oba scalone).
func Subtract(a, b []Range) []Range {
	b = Merge(b)
	var out []Range
	for _, r := range Merge(a) {
		cur := []Range{r}
		for _, x := range b {
			var next []Range
			for _, c := range cur {
				if x.End < c.Start || x.Start > c.End {
					next = append(next, c)
					continue
				}
				if x.Start > c.Start {
					next = append(next, Range{c.Start, x.Start - 1})
				}
				if x.End < c.End {
					next = append(next, Range{x.End + 1, c.End})
				}
			}
			cur = next
		}
		out = append(out, cur...)
	}
	return out
}

// Intersect zwraca część wspólną dwóch zbiorów zakresów.
func Intersect(a, b []Range) []Range {
	a, b = Merge(a), Merge(b)
	var out []Range
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		s := max(a[i].Start, b[j].Start)
		e := min(a[i].End, b[j].End)
		if s <= e {
			out = append(out, Range{s, e})
		}
		if a[i].End < b[j].End {
			i++
		} else {
			j++
		}
	}
	return out
}

func Total(rs []Range) uint64 {
	var n uint64
	for _, r := range rs {
		n += r.Size()
	}
	return n
}

func ContainsU32(rs []Range, v uint32) bool {
	i := sort.Search(len(rs), func(i int) bool { return rs[i].End >= v })
	return i < len(rs) && rs[i].Start <= v
}

// Contains sprawdza, czy adres należy do (scalonych) zakresów.
func Contains(rs []Range, ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil || !a.Unmap().Is4() {
		return false
	}
	return ContainsU32(rs, AddrToU32(a.Unmap()))
}

// Cursor wskazuje pozycję w liście zakresów przebiegu.
type Cursor struct {
	Idx    int    `json:"idx"`
	Offset uint64 `json:"off"`
}

// Take wycina z listy zakresów maksymalnie n adresów od kursora.
func Take(rs []Range, c Cursor, n uint64) ([]Range, Cursor) {
	var out []Range
	for n > 0 && c.Idx < len(rs) {
		r := rs[c.Idx]
		start := uint64(r.Start) + c.Offset
		remain := uint64(r.End) - start + 1
		take := min(remain, n)
		out = append(out, Range{uint32(start), uint32(start + take - 1)})
		n -= take
		if take == remain {
			c.Idx++
			c.Offset = 0
		} else {
			c.Offset += take
		}
	}
	return out, c
}

// Remaining liczy adresy pozostałe od kursora.
func Remaining(rs []Range, c Cursor) uint64 {
	var n uint64
	for i := c.Idx; i < len(rs); i++ {
		n += rs[i].Size()
		if i == c.Idx {
			n -= c.Offset
		}
	}
	return n
}

// Expand zamienia zakresy na listę adresów (pomija adres sieci/broadcast dla pełnych /24 i mniejszych bloków, jeśli skipEdges).
func Expand(rs []Range, skipEdges bool, fn func(netip.Addr)) {
	for _, r := range rs {
		for v := uint64(r.Start); v <= uint64(r.End); v++ {
			u := uint32(v)
			if skipEdges && (u&0xFF == 0 || u&0xFF == 0xFF) {
				continue
			}
			fn(U32ToAddr(u))
		}
	}
}

// Special zwraca true dla adresów, których nie wolno skanować bez jawnej zgody.
func Special(a netip.Addr) bool {
	return a.IsLoopback() || a.IsMulticast() || a.IsLinkLocalUnicast() || a.IsUnspecified() || a.IsInterfaceLocalMulticast()
}

// ---------------- Scope ----------------

// Scope łączy listę dozwolonych zakresów i wykluczeń.
type Scope struct {
	Allow    []Range
	Exclude  []Range
	Allow6   []netip.Prefix
	ExclHost map[string]bool
}

func NewScope(allow, exclude []string) Scope {
	s := Scope{ExclHost: map[string]bool{}}
	for _, a := range allow {
		if p, err := netip.ParsePrefix(a); err == nil {
			if p.Addr().Is4() {
				s.Allow = append(s.Allow, PrefixRange(p))
			} else {
				s.Allow6 = append(s.Allow6, p)
			}
		} else if t, err := ParseTarget(a); err == nil {
			s.Allow = append(s.Allow, t.Ranges...)
		}
	}
	for _, e := range exclude {
		if t, err := ParseTarget(e); err == nil {
			if t.Kind == "domain" {
				s.ExclHost[t.Value] = true
			} else {
				s.Exclude = append(s.Exclude, t.Ranges...)
			}
		} else if p, err := netip.ParsePrefix(e); err == nil && p.Addr().Is4() {
			s.Exclude = append(s.Exclude, PrefixRange(p))
		}
	}
	s.Allow = Merge(s.Allow)
	s.Exclude = Merge(s.Exclude)
	return s
}

// Allowed sprawdza pojedynczy adres.
func (s Scope) Allowed(ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap()
	if a.Is4() {
		v := AddrToU32(a)
		return ContainsU32(s.Allow, v) && !ContainsU32(s.Exclude, v)
	}
	for _, p := range s.Allow6 {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// Clip zwraca część zakresów dozwoloną przez scope (bez wykluczeń) i informację, ile odrzucono.
func (s Scope) Clip(rs []Range) ([]Range, uint64) {
	in := Intersect(rs, s.Allow)
	in = Subtract(in, s.Exclude)
	return in, Total(Merge(rs)) - Total(in)
}

// ---------------- Porty ----------------

// ParsePorts interpretuje specyfikację portów: "22,80,8000-8100,top-100,top-1000".
func ParsePorts(spec string) ([]int, error) {
	set := map[int]bool{}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(strings.ToLower(part))
		if part == "" {
			continue
		}
		switch part {
		case "top-100", "top100":
			ps, _ := ParsePorts(top100TCP)
			for _, p := range ps {
				set[p] = true
			}
			continue
		case "top-1000", "top1000":
			ps, _ := ParsePorts(top1000TCP)
			for _, p := range ps {
				set[p] = true
			}
			continue
		case "all", "1-65535":
			for p := 1; p <= 65535; p++ {
				set[p] = true
			}
			continue
		}
		if i := strings.Index(part, "-"); i > 0 {
			a, err1 := strconv.Atoi(part[:i])
			b, err2 := strconv.Atoi(part[i+1:])
			if err1 != nil || err2 != nil || a < 1 || b > 65535 || a > b {
				return nil, fmt.Errorf("niepoprawny zakres portów %q", part)
			}
			for p := a; p <= b; p++ {
				set[p] = true
			}
			continue
		}
		p, err := strconv.Atoi(part)
		if err != nil || p < 1 || p > 65535 {
			return nil, fmt.Errorf("niepoprawny port %q", part)
		}
		set[p] = true
	}
	out := make([]int, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Ints(out)
	return out, nil
}

// FormatPorts kompresuje listę portów do specyfikacji z zakresami.
func FormatPorts(ps []int) string {
	if len(ps) == 0 {
		return ""
	}
	sort.Ints(ps)
	var b strings.Builder
	start, prev := ps[0], ps[0]
	flush := func() {
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		if start == prev {
			b.WriteString(strconv.Itoa(start))
		} else {
			b.WriteString(strconv.Itoa(start) + "-" + strconv.Itoa(prev))
		}
	}
	for _, p := range ps[1:] {
		if p == prev {
			continue
		}
		if p == prev+1 {
			prev = p
			continue
		}
		flush()
		start, prev = p, p
	}
	flush()
	return b.String()
}

// IntersectPorts zwraca porty obecne w obu listach.
func IntersectPorts(a, b []int) []int {
	m := map[int]bool{}
	for _, p := range b {
		m[p] = true
	}
	var out []int
	for _, p := range a {
		if m[p] {
			out = append(out, p)
		}
	}
	return out
}

// PortSet to zbiór portów do szybkiego sprawdzania.
type PortSet map[int]bool

func NewPortSet(spec string) PortSet {
	ps, _ := ParsePorts(spec)
	s := PortSet{}
	for _, p := range ps {
		s[p] = true
	}
	return s
}

func mustPrefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }
