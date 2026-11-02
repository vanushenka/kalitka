//go:build linux

package awg

import (
	"strings"
	"testing"
)

// Needs no privileges: the check comes before anything is opened.
func TestCreateInterfaceRefusesABusyName(t *testing.T) {
	_, err := createInterface("lo", 1280)
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("got %v", err)
	}
}

func TestHasNetAdmin(t *testing.T) {
	for status, want := range map[string]bool{
		"Name:\tkalitka\nCapEff:\t000001ffffffffff\nCapBnd:\t0\n": true,
		"CapEff:\t0000000000001000\n":                             true,
		"CapEff:\t0000000000000000\n":                             false,
		"CapEff:\t0000000000000fff\n":                             false,
		// Another capability line must not count.
		"CapPrm:\t000001ffffffffff\nCapEff:\t0000000000000000\n": false,
	} {
		got, err := hasNetAdmin(status)
		if err != nil {
			t.Errorf("%q: %v", status, err)
		}
		if got != want {
			t.Errorf("%q: got %v", status, got)
		}
	}
	for _, status := range []string{"", "Name:\tkalitka\n", "CapEff:\tnot-hex\n"} {
		if _, err := hasNetAdmin(status); err == nil {
			t.Errorf("%q: accepted", status)
		}
	}
}
