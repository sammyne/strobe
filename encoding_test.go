package strobe_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/sammyne/strobe"
)

func TestStrobe_MarshalJSON(t *testing.T) {
	s, err := strobe.New("json test", strobe.Bit128)
	if err != nil {
		t.Fatalf("fail to new instance: %v", err)
	}

	sJSON, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("fail to marshal as JSON: %v", err)
	}

	var ss strobe.Strobe
	if err := json.Unmarshal(sJSON, &ss); err != nil {
		t.Fatalf("fail to unmarshal from JSON: %v", err)
	}

	ssJSON, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("fail to marshal as JSON: %v", err)
	}

	if !bytes.Equal(sJSON, ssJSON) {
		t.Fatalf("mismatched JSON: expect %q, got %q", string(sJSON), string(ssJSON))
	}
}
