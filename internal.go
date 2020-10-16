package strobe

import (
	"encoding/binary"

	"github.com/sammyne/strobe/sha3"
)

func (s *Strobe) beginOp(flags Flag) {
	if flags&FlagT != 0 { // decide role and renew flags if necessary
		if s.i0 == Undecided {
			s.i0 = Initiator << (flags & FlagI)
		}
		if s.i0 == Responder {
			flags &= 0xfe
		}
	}

	old := byte(s.posBegin)
	s.posBegin = s.pos + 1

	s.mustDuplex([]byte{old, byte(flags)}, false, false, flags&(FlagC|FlagK) != 0)
}

// must_duplex update data in place
func (s *Strobe) mustDuplex(data []byte, cbefore, cafter, forceF bool) {
	if cbefore && cafter {
		panic("both cbefore and cafter are set")
	}

	var maskBefore byte
	if cbefore {
		maskBefore = 0xff
	}

	// @TODO: optimize with bitmask
	for i := range data {
		data[i] ^= (s.st[s.pos] & maskBefore)
		s.st[s.pos] ^= data[i]
		if cafter {
			data[i] = s.st[s.pos]
		}

		s.pos++
		if s.pos == s.r {
			s.runF()
		}
	}

	if forceF && s.pos != 0 {
		s.runF()
	}
}

func (s *Strobe) operate(flags Flag, data []byte, more bool) ([]byte, error) {
	if (flags & (FlagK | 1<<6 | 1<<7)) != 0 {
		panic("not implemented")
	}

	if !more {
		s.beginOp(flags)
		s.curFlags = flags
	} else if s.curFlags != flags {
		panic("not supported")
	}

	cafter := (flags & (FlagC | FlagI | FlagT)) == (FlagC | FlagT)
	cbefore := ((flags & FlagC) != 0) && !cafter
	s.mustDuplex(data, cbefore, cafter, false)

	proccessed := data

	switch {
	case flags&(FlagI|FlagA) == (FlagI | FlagA):
		return proccessed, nil
	case flags&(FlagI|FlagT) == FlagT:
		return proccessed, nil
	case flags&(FlagI|FlagA|FlagT) == (FlagI | FlagT):
		if more {
			panic("not supported")
		}

		for _, v := range proccessed {
			if v != 0 {
				return nil, ErrAuthenticationFailed
			}
		}

		return nil, nil
	default:
	}

	return nil, nil
}

func (s *Strobe) output(flags Flag, more bool, out []byte) error {
	if !((flags&(FlagI|FlagT) != (FlagI | FlagT)) && (flags&(FlagI|FlagA) != FlagA)) {
		panic("not supported")
	}

	for i := range out {
		out[i] = 0
	}

	_, err := s.operate(flags, out, more)
	return err
}

func (s *Strobe) runF() {
	if s.initialized {
		s.st[s.pos] ^= byte(s.posBegin)
		s.st[s.pos+1] ^= 0x04
		s.st[s.r+1] ^= 0x80
	}

	s.st = s.renewKeccakState()

	s.pos, s.posBegin = 0, 0
}

func (s *Strobe) renewKeccakState() []byte {
	for i, j := 0, 0; i+8 <= len(s.st); i, j = i+8, j+1 {
		s.keccakState[j] = binary.LittleEndian.Uint64(s.st[i:])
	}

	sha3.KeccakF1600(&s.keccakState)

	for i, j := 0, 0; i+8 <= len(s.st); i, j = i+8, j+1 {
		binary.LittleEndian.PutUint64(s.st[i:], s.keccakState[j])
	}

	return s.st
}

// frameIf switch on the FlagM for the given flag
func frameIf(flag Flag, yes bool) Flag {
	if yes {
		flag |= FlagM
	}

	return flag
}
