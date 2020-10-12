package strobe

import "encoding/json"

type strobeJSON struct {
	CurFlags    Flag
	Initialized bool
	I0          Role
	Pos         int
	PosBegin    int
	R           int
	State       []byte
	KeccakState []uint64
}

// MarshalJSON marshals the instance as JSON to export.
func (s *Strobe) MarshalJSON() ([]byte, error) {
	ss := strobeJSON{
		CurFlags:    s.curFlags,
		Initialized: s.initialized,
		I0:          s.i0,
		Pos:         s.pos,
		PosBegin:    s.posBegin,
		R:           s.r,
		State:       s.st,
		KeccakState: s.keccakState[:],
	}

	return json.Marshal(ss)
}

// UnmarshalJSON unmarshals instance from JSON.
// The given data should be that has been exported by MarshalJSON.
func (s *Strobe) UnmarshalJSON(data []byte) error {
	var ss strobeJSON
	if err := json.Unmarshal(data, &ss); err != nil {
		return err
	}

	s.curFlags = ss.CurFlags
	s.initialized = ss.Initialized
	s.i0 = ss.I0
	s.pos = ss.Pos
	s.posBegin = ss.PosBegin
	s.r = ss.R
	s.st = ss.State
	copy(s.keccakState[:], ss.KeccakState)

	return nil
}
