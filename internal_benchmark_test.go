package strobe

import (
	"crypto/rand"
	"testing"
)

func BenchmarkStrobe_mustDuplex(b *testing.B) {
	s, err := New("hello-world", Bit128)
	if err != nil {
		b.Fatalf("fail to New: %v", err)
	}

	var data [8096]byte
	if _, err := rand.Read(data[:]); err != nil {
		b.Fatalf("fail to Read rand bytes: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d := data
		s.mustDuplex(d[:], true, false, false)
	}
}
