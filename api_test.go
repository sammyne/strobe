package strobe_test

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"testing"

	"github.com/sammyne/strobe"
)

func TestStrobe_AD_Streaming(t *testing.T) {
	testVector := []struct {
		msg1          string
		msg2          string
		proto         string
		securityLevel strobe.SecurityLevel
	}{
		{
			"hello",
			"world",
			"good morning",
			strobe.Bit128,
		},
	}

	for i, c := range testVector {
		nonStreaming := mustNewStrobe(t, c.proto, c.securityLevel)
		nonStreamingOpts := strobe.Options{}

		if err := nonStreaming.AD([]byte(c.msg1+c.msg2), &nonStreamingOpts); err != nil {
			t.Fatalf("#%d unexpected error during non-streaming AD: %v", i, err)
		}
		expect, err := nonStreaming.PRF(32)
		if err != nil {
			t.Fatalf("#%d unexpected error during non-streaming PRF: %v", i, err)
		}

		streaming := mustNewStrobe(t, c.proto, c.securityLevel)
		streamingOpts := strobe.Options{Streaming: true}
		if err := streaming.AD([]byte(c.msg1), &nonStreamingOpts); err != nil {
			t.Fatalf("#%d unexpected error during the 1st streaming AD: %v", i, err)
		}
		if err := streaming.AD([]byte(c.msg2), &streamingOpts); err != nil {
			t.Fatalf("#%d unexpected error during the 2nd streaming AD: %v", i, err)
		}

		got, err := streaming.PRF(32)
		if err != nil {
			t.Fatalf("#%d unexpected error during non-streaming PRF: %v", i, err)
		}

		if !bytes.Equal(expect, got) {
			t.Fatalf("#%d failed: expect %x, got %x\n", i, expect, got)
		}
	}
}

func TestStrobe_AD(t *testing.T) {
	raw := mustReadFile(t, "testdata/ad_then_prf.json")
	var testVector []TestVector4AD
	if err := json.Unmarshal(raw, &testVector); err != nil {
		t.Fatalf("fail to parse test vector: %v", err)
	}

	for i, v := range testVector {
		securityLevel := strobe.SecurityLevel(v.SecurityLevel)
		for j, c := range v.Cases {
			s := mustNewStrobe(t, v.Proto, securityLevel)

			opts := &strobe.Options{Meta: c.WithMeta}
			if err := s.AD(c.Data, opts); err != nil {
				t.Fatalf("#%d-%d AD failed: %v", i, j, err)
			}

			if got, err := s.PRF(len(c.PRF)); err != nil {
				t.Fatalf("#%d-%d PRF failed: %v", i, j, err)
			} else if !bytes.Equal(c.PRF, got) {
				t.Fatalf("#%d-%d failed: expect %x, got %x", i, j, c.PRF, got)
			}
		}
	}
}

func TestStrobe_KEY(t *testing.T) {
	type TestCase struct {
		Key []byte // data input for AD
		PRF []byte // PRF out
	}

	type TestVector struct {
		Proto         string
		SecurityLevel int
		Cases         []TestCase
	}

	raw := mustReadFile(t, "testdata/key_then_prf.json")
	var testVector []TestVector
	if err := json.Unmarshal(raw, &testVector); err != nil {
		t.Fatalf("fail to parse test vector: %v", err)
	}

	for i, v := range testVector {
		securityLevel := strobe.SecurityLevel(v.SecurityLevel)
		for j, c := range v.Cases {
			s := mustNewStrobe(t, v.Proto, securityLevel)

			if err := s.KEY(c.Key, false); err != nil {
				t.Fatalf("#%d-%d KEY failed: %v", i, j, err)
			}

			got, err := s.PRF(len(c.PRF))
			if err != nil {
				t.Fatalf("#%d-%d PRF failed: %v", i, j, err)
			}

			if !bytes.Equal(c.PRF, got) {
				t.Fatalf("#%d-%d failed: expect %x, got %x", i, j, c.PRF, got)
			}
		}
	}
}

func TestStrobe_RATCHET(t *testing.T) {
	type TestCase struct {
		Length int
		PRF    []byte // PRF out
	}

	type TestVector struct {
		Proto         string
		SecurityLevel int
		Cases         []TestCase
	}

	raw := mustReadFile(t, "testdata/ratchet_then_prf.json")
	var testVector []TestVector
	if err := json.Unmarshal(raw, &testVector); err != nil {
		t.Fatalf("fail to parse test vector: %v", err)
	}

	for i, v := range testVector {
		securityLevel := strobe.SecurityLevel(v.SecurityLevel)
		for j, c := range v.Cases {
			s := mustNewStrobe(t, v.Proto, securityLevel)

			if err := s.RATCHET(c.Length); err != nil {
				t.Fatalf("#%d-%d KEY failed: %v", i, j, err)
			}

			got, err := s.PRF(len(c.PRF))
			if err != nil {
				t.Fatalf("#%d-%d PRF failed: %v", i, j, err)
			}

			if !bytes.Equal(c.PRF, got) {
				t.Fatalf("#%d-%d failed: expect %x, got %x", i, j, c.PRF, got)
			}
		}
	}
}

func TestStrobe_RecvCLR(t *testing.T) {
	type TestCase struct {
		Plaintext []byte
		PRF       []byte
		Meta      bool
	}

	type TestVector struct {
		Proto         string
		SecurityLevel int
		Cases         []TestCase
	}

	raw := mustReadFile(t, "testdata/send_then_recv_clr.json")
	var testVector []TestVector
	if err := json.Unmarshal(raw, &testVector); err != nil {
		t.Fatalf("fail to parse test vector: %v", err)
	}

	for i, v := range testVector {
		securityLevel := strobe.SecurityLevel(v.SecurityLevel)
		for j, c := range v.Cases {
			s := mustNewStrobe(t, v.Proto, securityLevel)

			opts := strobe.Options{Meta: c.Meta}
			if err := s.RecvCLR(c.Plaintext, &opts); err != nil {
				t.Fatalf("#%d-%d RecvCLR failed: %v", i, j, err)
			}

			if got, err := s.PRF(len(c.PRF)); err != nil {
				t.Fatalf("#%d-%d PRF failed: %v", i, j, err)
			} else if !bytes.Equal(c.PRF, got) {
				t.Fatalf("#%d-%d failed: expect %x, got %x", i, j, c.PRF, got)
			}
		}
	}
}

func TestStrobe_RecvENC(t *testing.T) {
	type TestCase struct {
		Key        []byte
		Meta       bool
		Plaintext  []byte
		Ciphertext []byte
	}

	type TestVector struct {
		Proto         string
		SecurityLevel int
		Cases         []TestCase
	}

	raw := mustReadFile(t, "testdata/send_then_recv_enc.json")
	var testVector []TestVector
	if err := json.Unmarshal(raw, &testVector); err != nil {
		t.Fatalf("fail to parse test vector: %v", err)
	}

	for i, v := range testVector {
		securityLevel := strobe.SecurityLevel(v.SecurityLevel)
		for j, c := range v.Cases {
			s := mustNewStrobe(t, v.Proto, securityLevel)
			_ = s.KEY(c.Key, false)

			opts := strobe.Options{Meta: c.Meta}
			if got, err := s.RecvENC(c.Ciphertext, &opts); err != nil {
				t.Fatalf("#%d-%d RecvENC failed: %v", i, j, err)
			} else if !bytes.Equal(c.Plaintext, got) {
				t.Fatalf("#%d-%d invalid plaintext: expect %x, got %x", i, j, c.Plaintext, got)
			}
		}
	}
}

func TestStrobe_RecvMAC(t *testing.T) {
	type TestCase struct {
		Key  []byte
		MAC  []byte
		Meta bool
	}

	type TestVector struct {
		Proto         string
		SecurityLevel int
		Cases         []TestCase
	}

	raw := mustReadFile(t, "testdata/key_then_mac.json")
	var testVector []TestVector
	if err := json.Unmarshal(raw, &testVector); err != nil {
		t.Fatalf("fail to parse test vector: %v", err)
	}

	for i, v := range testVector {
		securityLevel := strobe.SecurityLevel(v.SecurityLevel)
		for j, c := range v.Cases {
			s := mustNewStrobe(t, v.Proto, securityLevel)
			_ = s.KEY(c.Key, false)

			opts := strobe.Options{Meta: c.Meta}
			if err := s.RecvMAC(c.MAC, &opts); err != nil {
				t.Fatalf("#%d-%d RecvMAC failed: %v", i, j, err)
			}
		}
	}
}

func TestStrobe_SendCLR(t *testing.T) {
	type TestCase struct {
		Plaintext []byte
		PRF       []byte
		Meta      bool
	}

	type TestVector struct {
		Proto         string
		SecurityLevel int
		Cases         []TestCase
	}

	raw := mustReadFile(t, "testdata/send_then_recv_clr.json")
	var testVector []TestVector
	if err := json.Unmarshal(raw, &testVector); err != nil {
		t.Fatalf("fail to parse test vector: %v", err)
	}

	for i, v := range testVector {
		securityLevel := strobe.SecurityLevel(v.SecurityLevel)
		for j, c := range v.Cases {
			s := mustNewStrobe(t, v.Proto, securityLevel)

			opts := strobe.Options{Meta: c.Meta}
			if err := s.SendCLR(c.Plaintext, &opts); err != nil {
				t.Fatalf("#%d-%d SendCLR failed: %v", i, j, err)
			}

			if got, err := s.PRF(len(c.PRF)); err != nil {
				t.Fatalf("#%d-%d PRF failed: %v", i, j, err)
			} else if !bytes.Equal(c.PRF, got) {
				t.Fatalf("#%d-%d failed: expect %x, got %x", i, j, c.PRF, got)
			}
		}
	}
}

func TestStrobe_SendENC(t *testing.T) {
	type TestCase struct {
		Key        []byte
		Meta       bool
		Plaintext  []byte
		Ciphertext []byte
	}

	type TestVector struct {
		Proto         string
		SecurityLevel int
		Cases         []TestCase
	}

	raw := mustReadFile(t, "testdata/send_then_recv_enc.json")
	var testVector []TestVector
	if err := json.Unmarshal(raw, &testVector); err != nil {
		t.Fatalf("fail to parse test vector: %v", err)
	}

	for i, v := range testVector {
		securityLevel := strobe.SecurityLevel(v.SecurityLevel)
		for j, c := range v.Cases {
			s := mustNewStrobe(t, v.Proto, securityLevel)
			_ = s.KEY(c.Key, false)

			opts := strobe.Options{Meta: c.Meta}
			if got, err := s.SendENC(c.Plaintext, &opts); err != nil {
				t.Fatalf("#%d-%d SendENC failed: %v", i, j, err)
			} else if !bytes.Equal(c.Ciphertext, got) {
				t.Fatalf("#%d-%d invalid ciphertext: expect %x, got %x", i, j, c.Ciphertext, got)
			}
		}
	}
}

func TestStrobe_SendMAC(t *testing.T) {
	type TestCase struct {
		Key  []byte
		MAC  []byte
		Meta bool
	}

	type TestVector struct {
		Proto         string
		SecurityLevel int
		Cases         []TestCase
	}

	raw := mustReadFile(t, "testdata/key_then_mac.json")
	var testVector []TestVector
	if err := json.Unmarshal(raw, &testVector); err != nil {
		t.Fatalf("fail to parse test vector: %v", err)
	}

	for i, v := range testVector {
		securityLevel := strobe.SecurityLevel(v.SecurityLevel)
		for j, c := range v.Cases {
			s := mustNewStrobe(t, v.Proto, securityLevel)
			_ = s.KEY(c.Key, false)

			opts := strobe.Options{Meta: c.Meta}
			if got, err := s.SendMAC(len(c.MAC), &opts); err != nil {
				t.Fatalf("#%d-%d SendMAC failed: %v", i, j, err)
			} else if !bytes.Equal(c.MAC, got) {
				t.Fatalf("#%d-%d invalid MAC: expect %x, got %x", i, j, c.MAC, got)
			}
		}
	}
}

type TestVector4AD struct {
	Proto         string
	SecurityLevel int
	Cases         []TestCase4AD
}

type TestCase4AD struct {
	Data     []byte // data input for AD
	WithMeta bool   // with meta or not
	PRF      []byte // PRF out
}

func mustNewStrobe(t *testing.T, proto string, securityLevel strobe.SecurityLevel) *strobe.Strobe {
	s, err := strobe.New(proto, securityLevel)
	if err != nil {
		t.Fatalf("failed to initialize strobe: %v", err)
	}

	return s
}

func mustReadFile(t *testing.T, filename string) []byte {
	raw, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}

	return raw
}
