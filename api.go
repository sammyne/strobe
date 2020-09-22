package strobe

import (
	"github.com/sammyne/strobe/sha3"
)

type Options struct {
	Meta      bool
	Streaming bool
}

type Strobe struct {
	curFlags    Flag
	initialized bool
	i0          Role
	pos         int
	posBegin    int
	r           int // R
	st          []byte

	keccakState [sha3.StateLen / 8]uint64
}

//func (s *Strobe) AD(data []byte, more bool) error {
func (s *Strobe) AD(data []byte, opts *Options) error {
	flag := FlagA
	if opts.Meta {
		flag |= FlagM
	}

	_, err := s.operate(flag, data, opts.Streaming)
	return err
}

func (s *Strobe) KEY(data []byte, streaming bool) error {
	_, err := s.operate(FlagA|FlagC, data, streaming)
	return err
}

func (s *Strobe) PRF(length int) ([]byte, error) {
	return s.operateOnInt(FlagI|FlagA|FlagC, length, false)
}

func (s *Strobe) RATCHET(length int) error {
	_, err := s.operateOnInt(FlagC, length, false)
	return err
}

func (s *Strobe) RecvCLR(data []byte, opts *Options) error {
	flag := FlagI | FlagA | FlagT
	if opts.Meta {
		flag |= FlagM
	}

	_, err := s.operate(flag, data, opts.Streaming)
	return err
}

func (s *Strobe) RecvENC(data []byte, opts *Options) ([]byte, error) {
	flag := FlagI | FlagA | FlagC | FlagT
	if opts.Meta {
		flag |= FlagM
	}

	return s.operate(flag, data, opts.Streaming)
}

func (s *Strobe) RecvMAC(mac []byte, opts *Options) error {
	flag := FlagI | FlagC | FlagT
	if opts.Meta {
		flag |= FlagM
	}

	_, err := s.operate(flag, mac, opts.Streaming)
	return err
}

func (s *Strobe) SendCLR(data []byte, opts *Options) error {
	flag := FlagA | FlagT
	if opts.Meta {
		flag |= FlagM
	}

	_, err := s.operate(flag, data, opts.Streaming)
	return err
}

func (s *Strobe) SendENC(data []byte, opts *Options) ([]byte, error) {
	flag := FlagA | FlagC | FlagT
	if opts.Meta {
		flag |= FlagM
	}

	return s.operate(flag, data, opts.Streaming)
}

func (s *Strobe) SendMAC(length int, opts *Options) ([]byte, error) {
	flag := FlagC | FlagT
	if opts.Meta {
		flag |= FlagM
	}

	return s.operateOnInt(flag, length, opts.Streaming)
}

// @note Only KeccakF1600 is supported for now
func New(proto string, level SecurityLevel) (*Strobe, error) {
	if level != Bit128 && level != Bit256 {
		return nil, ErrInvalidSecurityLevel
	}

	out := &Strobe{
		i0:       None,
		r:        sha3.StateLen - int(level)/4,
		st:       make([]byte, sha3.StateLen),
		curFlags: FlagNone,
	}

	domain := append([]byte{1, byte(out.r), 1, 0, 1, 12 * 8}, []byte(MagicASCII)...)
	out.mustDuplex(domain, false, false, true)

	//out.renewKeccakState()
	//fmt.Printf("%x\n", out.st)
	//return out, nil

	//fmt.Println("----")

	// cSHAKE separation is done.
	// Turn on Strobe padding and do per-proto separation
	out.r -= 2
	out.initialized = true
	if _, err := out.operate(FlagA|FlagM, []byte(proto), false); err != nil {
		return nil, err
	}

	return out, nil
}
