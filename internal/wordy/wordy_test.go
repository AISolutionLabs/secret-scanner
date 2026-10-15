package wordy

import (
	"math/rand"
	"reflect"
	"testing"
)

func TestTokens(t *testing.T) {
	got := Tokens("parseHTTPRequest2xx_SecurityProfiles.esnext-map")
	want := []string{"parse", "HTTP", "Request", "xx", "Security", "Profiles", "esnext", "map"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Tokens = %v", got)
	}
}

func TestWordinessSeparates(t *testing.T) {
	for _, w := range []string{"SecurityProfiles", "isOnDemandRevalidate", "key-2024-primary", "Service-Worker-Allowed",
		"AssociationSummaries", "handlerContext", "throwIfRequested"} {
		if Wordiness(w) < 0.6 {
			t.Errorf("%s should be wordy (%.2f)", w, Wordiness(w))
		}
	}
	r := rand.New(rand.NewSource(1))
	const cs = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	high := 0
	for i := 0; i < 2000; i++ {
		b := make([]byte, 24)
		for j := range b {
			b[j] = cs[r.Intn(len(cs))]
		}
		if Wordiness(string(b)) >= 0.6 {
			high++
		}
	}
	if high > 4 { // < 0.2% of random tokens may be dropped
		t.Errorf("%d/2000 random tokens scored as wordy", high)
	}
}
