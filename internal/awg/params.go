package awg

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"regexp"
)

const (
	// maxJunkCount is the installer's ceiling: together with I1-I5 a larger Jc can
	// overflow the batch of 128 packets and crash amneziawg-go on the first
	// handshake (amneziawg-go#111).
	maxJunkCount = 122
	maxJunkSize  = 1280
	// minPadding is the header protection nonce size: amneziawg-go rejects a
	// config with a smaller S1-S4 once HeaderProtectionKey is set.
	minPadding = 12
	maxPadding = 1280
)

var (
	headerFormat  = regexp.MustCompile(`^[0-9]{1,10}(-[0-9]{1,10})?$`)
	paddingFormat = regexp.MustCompile(`^[0-9]{1,5}(-[0-9]{1,5})?$`)
	// signatureFormat holds the tags both the kernel module and amneziawg-go
	// understand; a config with `<c>` does not come up on amneziawg-go.
	signatureFormat = regexp.MustCompile(`^(<(b 0x([0-9a-fA-F]{2})+|r [0-9]{1,4}|rd [0-9]{1,4}|rc [0-9]{1,4}|t)>)*$`)
)

// Params holds the obfuscation settings of one AmneziaWG 3.1 tunnel. Both ends of
// a tunnel use the same values.
type Params struct {
	Jc                     int    `json:"jc"`
	Jmin                   int    `json:"jmin"`
	Jmax                   int    `json:"jmax"`
	S1                     int    `json:"s1"`
	S2                     int    `json:"s2"`
	S3                     int    `json:"s3"`
	S4                     int    `json:"s4"`
	H1                     string `json:"h1"`
	H2                     string `json:"h2"`
	H3                     string `json:"h3"`
	H4                     string `json:"h4"`
	I1                     string `json:"i1"`
	HeaderProtectionKey    string `json:"header_protection_key"`
	ContentPaddingAddition string `json:"content_padding_addition"`
}

// NewParams generates an AmneziaWG 3.1 profile. The ranges and the size rules
// follow generate_awg_params in bivlked/amneziawg-installer (MIT), so the profile
// stays within what that project has measured on real networks.
func NewParams() Params {
	jmin := randRange(40, 89)
	p := Params{
		Jc:   randRange(3, 6),
		Jmin: jmin,
		Jmax: jmin + randRange(50, 250),
		S1:   randRange(15, 150),
		S2:   randRange(15, 150),
		S3:   randRange(minPadding, 55),
		// With a header protection key the wire looks random for any H, so random
		// ranges hide nothing; the values must only not overlap.
		H1:                     "1",
		H2:                     "2",
		H3:                     "3",
		H4:                     "4",
		I1:                     newSignaturePacket(),
		HeaderProtectionKey:    GenerateKey(),
		ContentPaddingAddition: "32-128",
	}
	for handshakeSizesMatch(p.S1, p.S2, p.S3) {
		p.S2 = randRange(15, 150)
		p.S3 = randRange(minPadding, 55)
	}
	var free []int
	for s4 := minPadding; s4 <= 27; s4++ {
		if !dataSizeCollides(p.S1, p.S2, p.S3, s4) {
			free = append(free, s4)
		}
	}
	// Each collision rule forbids one residue of S4 modulo 16 and the range holds
	// 16 values, so free is never empty.
	p.S4 = free[randRange(0, len(free)-1)]
	return p
}

// Validate checks every field. Params can arrive from another machine inside an
// invite, and the values are written to a config that awg-quick parses, so a value
// must not be able to add a line such as PostUp to it.
func (p Params) Validate() error {
	if p.Jc < 0 || p.Jc > maxJunkCount {
		return fmt.Errorf("Jc %d is outside 0-%d", p.Jc, maxJunkCount)
	}
	if p.Jmin < 0 || p.Jmax > maxJunkSize || p.Jmin > p.Jmax {
		return fmt.Errorf("Jmin %d and Jmax %d do not form a range within 0-%d", p.Jmin, p.Jmax, maxJunkSize)
	}
	for i, s := range []int{p.S1, p.S2, p.S3, p.S4} {
		if s < minPadding || s > maxPadding {
			return fmt.Errorf("S%d %d is outside %d-%d", i+1, s, minPadding, maxPadding)
		}
	}
	if handshakeSizesMatch(p.S1, p.S2, p.S3) {
		return errors.New("S1-S3 give two handshake messages the same size")
	}
	for i, h := range []string{p.H1, p.H2, p.H3, p.H4} {
		if !headerFormat.MatchString(h) {
			return fmt.Errorf("H%d %q is not a number or a range", i+1, h)
		}
	}
	if !signatureFormat.MatchString(p.I1) {
		return fmt.Errorf("I1 %q holds something other than the portable tags", p.I1)
	}
	if err := ValidateKey(p.HeaderProtectionKey); err != nil {
		return fmt.Errorf("HeaderProtectionKey: %w", err)
	}
	if !paddingFormat.MatchString(p.ContentPaddingAddition) {
		return fmt.Errorf("ContentPaddingAddition %q is not a number or a range", p.ContentPaddingAddition)
	}
	return nil
}

// handshakeSizesMatch reports whether two handshake messages end up the same size:
// init is 148 bytes + S1, response 92 + S2, cookie 64 + S3. The third match,
// S3 == S1+84, cannot happen within the generated ranges but can in an invite.
func handshakeSizesMatch(s1, s2, s3 int) bool {
	return s2 == s1+56 || s3 == s2+28 || s3 == s1+84
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
