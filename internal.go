package strobe

import (
	"encoding/binary"

	"github.com/sammyne/strobe/sha3"
)

func (s *Strobe) beginOp(flags Flag) {
	if flags&FlagT != 0 { // decide role and renew flags if necessary
		if s.i0 == None {
			s.i0 = Initiator << (flags & FlagI)
		}
		if s.i0 == Responder {
			flags &= 0xfe
		}
	}

	old := byte(s.posBegin)
	s.posBegin = s.pos + 1

	s.mustDuplex([]byte{old, byte(flags)}, false, false, flags&(FlagC|FlagK) != 0)

	//fmt.Printf("[beginOp] state: %x\n", s.st)
}

// must_duplex update data in place
func (s *Strobe) mustDuplex(data []byte, cbefore, cafter, forceF bool) {
	if cbefore && cafter {
		panic("both cbefore and cafter are set")
	}

	// fmt.Println("[must_duplex]", cbefore, cafter, s.pos)
	// fmt.Printf("[must_duplex] data: %x\n", data)
	// fmt.Printf("[must_duplex] state1: %x\n", s.st)

	// @TODO: optimize with bitmask
	for i := range data {
		if cbefore {
			data[i] ^= s.st[s.pos]
		}
		s.st[s.pos] ^= data[i]
		if cafter {
			data[i] = s.st[s.pos]
		}

		s.pos++
		if s.pos == s.r {
			s.runF()
		}
	}

	//fmt.Printf("[must_duplex] state2: %x\n", s.st)
	//fmt.Println("[must_duplex]:", forceF, s.pos)

	if forceF && s.pos != 0 {
		s.runF()
	}

	//fmt.Printf("[must_duplex] state3: %x\n", s.st)
	//fmt.Printf("[must_duplex] data: %x\n", data)
}

func (s *Strobe) operate(flags Flag, data []byte, more bool) ([]byte, error) {
	if (flags & (FlagK | 1<<6 | 1<<7)) != 0 {
		panic("not implemented")
	}

	//fmt.Printf("[operate] state1: %x\n", s.st)

	if !more {
		s.beginOp(flags)
		s.curFlags = flags
	} else if s.curFlags != flags {
		panic("not supported")
	}

	//fmt.Printf("[operate] state2: %x\n", s.st)

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

func (s *Strobe) operateOnInt(flags Flag, length int, more bool) ([]byte, error) {
	if !((flags&(FlagI|FlagT) != (FlagI | FlagT)) && (flags&(FlagI|FlagA) != FlagA)) {
		panic("not supported")
	}

	data := make([]byte, length)
	return s.operate(flags, data, more)
}

func (s *Strobe) runF() {
	if s.initialized {
		s.st[s.pos] ^= byte(s.posBegin)
		s.st[s.pos+1] ^= 0x04
		s.st[s.r+1] ^= 0x80
	}

	//fmt.Printf("[runF] state1: %x\n", s.st)

	s.st = s.renewKeccakState()

	//fmt.Printf("[runF] state2: %x\n", s.st)

	s.pos, s.posBegin = 0, 0
}

func (s *Strobe) renewKeccakState() []byte {

	//fmt.Printf("> state3: %x\n", s.st)
	for i, j := 0, 0; i+8 <= len(s.st); i, j = i+8, j+1 {
		s.keccakState[j] = binary.LittleEndian.Uint64(s.st[i:])
	}

	sha3.KeccakF1600(&s.keccakState)

	for i, j := 0, 0; i+8 <= len(s.st); i, j = i+8, j+1 {
		binary.LittleEndian.PutUint64(s.st[i:], s.keccakState[j])
	}

	//fmt.Printf("< state3: %x\n", s.st)

	return s.st
}
