package awg

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"regexp"
)

// The AmneziaWG 3.1 profile. The ranges and the size rules follow
// generate_awg_params in bivlked/amneziawg-installer (MIT), to stay within what that
// project has tried on real networks. S3 and S4 start at 12, the header protection
// nonce size: amneziawg-go rejects a smaller padding once a protection key is set.
var (
	junkCountRange        = intRange{3, 6}
	junkMinRange          = intRange{40, 89}
	junkSpreadRange       = intRange{50, 250} // Jmax - Jmin
	handshakePaddingRange = intRange{15, 150} // S1, S2
	cookiePaddingRange    = intRange{12, 55}  // S3
	transportPaddingRange = intRange{12, 27}  // S4
)

// signatureFormat is the exact shape newSignaturePacket builds: one or two answers
// give a 37 or 53-byte tail. It is also what bounds the size of I1, so a hostile
// invite cannot pass huge lengths to the engine.
var signatureFormat = regexp.MustCompile(`^<r 2><b 0x85800001000[12]00000000[0-9a-f]{2}><rc [2-6][0-9]><b 0x([0-9a-f]{74}|[0-9a-f]{106})>$`)

type intRange struct{ lo, hi int }

func (r intRange) random() int         { return randRange(r.lo, r.hi) }
func (r intRange) contains(v int) bool { return r.lo <= v && v <= r.hi }

// Params holds the obfuscation settings of one AmneziaWG 3.1 tunnel that differ
// between tunnels. Both ends of a tunnel use the same values.
type Params struct {
	Jc                  int    `json:"jc"`
	Jmin                int    `json:"jmin"`
	Jmax                int    `json:"jmax"`
	S1                  int    `json:"s1"`
	S2                  int    `json:"s2"`
	S3                  int    `json:"s3"`
	S4                  int    `json:"s4"`
	I1                  string `json:"i1"`
	HeaderProtectionKey string `json:"header_protection_key"`
}

// NewParams generates the settings of a new tunnel.
func NewParams() Params {
	jmin := junkMinRange.random()
	p := Params{
		Jc:                  junkCountRange.random(),
		Jmin:                jmin,
		Jmax:                jmin + junkSpreadRange.random(),
		S1:                  handshakePaddingRange.random(),
		S2:                  handshakePaddingRange.random(),
		S3:                  cookiePaddingRange.random(),
		I1:                  newSignaturePacket(),
		HeaderProtectionKey: GenerateKey(),
	}
	for handshakeSizesMatch(p.S1, p.S2, p.S3) {
		p.S2 = handshakePaddingRange.random()
		p.S3 = cookiePaddingRange.random()
	}
	var free []int
	for s4 := transportPaddingRange.lo; s4 <= transportPaddingRange.hi; s4++ {
		if !dataSizeCollides(p.S1, p.S2, p.S3, s4) {
			free = append(free, s4)
		}
	}
	// Each collision rule forbids one residue of S4 modulo 16 and the range holds
	// 16 values, so free is never empty.
	p.S4 = free[randRange(0, len(free)-1)]
	return p
}

// Validate accepts only what NewParams can generate. Params can arrive from another
// machine inside an invite, and the values are written to the engine's line-based
// config, so a value must not be able to add a line such as allowed_ip to it.
func (p Params) Validate() error {
	for _, field := range []struct {
		name  string
		value int
		want  intRange
	}{
		{"Jc", p.Jc, junkCountRange},
		{"Jmin", p.Jmin, junkMinRange},
		{"Jmax - Jmin", p.Jmax - p.Jmin, junkSpreadRange},
		{"S1", p.S1, handshakePaddingRange},
		{"S2", p.S2, handshakePaddingRange},
		{"S3", p.S3, cookiePaddingRange},
		{"S4", p.S4, transportPaddingRange},
	} {
		if !field.want.contains(field.value) {
			return fmt.Errorf("%s %d is outside %d-%d", field.name, field.value, field.want.lo, field.want.hi)
		}
	}
	if handshakeSizesMatch(p.S1, p.S2, p.S3) {
		return errors.New("S1-S3 give two handshake messages the same size")
	}
	if dataSizeCollides(p.S1, p.S2, p.S3, p.S4) {
		return errors.New("S1-S4 let a data packet pass for a handshake message")
	}
	if !signatureFormat.MatchString(p.I1) {
		return fmt.Errorf("I1 %q is not a generated signature packet", p.I1)
	}
	if err := ValidateKey(p.HeaderProtectionKey); err != nil {
		return fmt.Errorf("HeaderProtectionKey: %w", err)
	}
	// amneziawg-go treats an all-zero key as no key, which would turn protection off.
	if p.HeaderProtectionKey == zeroKey {
		return errors.New("HeaderProtectionKey is all zeros")
	}
	return nil
}

// handshakeSizesMatch reports whether two handshake messages end up the same size:
// init is 148 bytes + S1, response 92 + S2, cookie 64 + S3. The third pair cannot
// match within the ranges above.
func handshakeSizesMatch(s1, s2, s3 int) bool {
	return s2 == s1+56 || s3 == s2+28
}

// dataSizeCollides reports whether a receiver can take a data packet for a
// handshake message by its length (_awg_size_collisions in the installer).
func dataSizeCollides(s1, s2, s3, s4 int) bool {
	initiation := s1 - s4 + 116
	response := s2 - s4 + 60
	cookie := s3 - s4 + 32
	return initiation >= 32 && initiation%16 == 0 && initiation != 128 ||
		response >= 32 && response%16 == 0 ||
		cookie >= 48 && cookie%16 == 0
}

// newSignaturePacket builds I1 in the shape of a DNS answer, as generate_cps_i1 in
// the installer does. The installer measured this exact shape on real networks, so
// odd details such as the 0x8580 flags are deliberate and must stay. The random
// tags expand afresh in every packet, so two packets never match byte for byte.
func newSignaturePacket() string {
	const question = "0463646e730669636c6f756403636f6d0000010001" // cdns.icloud.com, type A, class IN
	label := randRange(20, 62)
	answers := randRange(1, 2)
	ttl := [...]string{"0000003c", "0000012c", "00000384", "00000e10"}[randRange(0, 3)]

	body := question
	for range answers {
		// Remapped rather than redrawn, so that 10 and 127 never appear and no other
		// value becomes more likely than the rest.
		first := randRange(1, 221)
		switch first {
		case 10:
			first = 222
		case 127:
			first = 223
		}
		body += fmt.Sprintf("c00c00010001%s0004%02x%02x%02x%02x",
			ttl, first, randRange(0, 255), randRange(0, 255), randRange(1, 254))
	}
	return fmt.Sprintf("<r 2><b 0x85800001%04x00000000%02x><rc %d><b 0x%s>", answers, label, label, body)
}

// randRange returns a random number in [lo, hi]. It panics on hi < lo: the callers
// pass constants, so that is a programming error.
func randRange(lo, hi int) int {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(hi-lo+1)))
	if err != nil {
		panic(fmt.Sprintf("awg: random number in [%d, %d]: %v", lo, hi, err))
	}
	return lo + int(n.Int64())
}
