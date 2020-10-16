// package strobe implements the STROBE@v1.0.2 framework.
//
// See also the specification https://strobe.sourceforge.io/specs/.
//
// @note Framing: A more complex protocol might have many dierent meanings for the same operation.
// A natural pattern to ensure parseability is to precede each operation with a comment in the
// transcript that disambiguates it. Such information is usually provided anyway through protocol
// framing.
//
package strobe

import (
	"github.com/sammyne/strobe/sha3"
)

// Options define common options for different operations.
type Options struct {
	// Meta specifies the data to operate on is meta.
	Meta bool
	// Meta specifies the data will be processed in a streaming fashion, one byte at a time.
	Streaming bool
}

// Strobe is the engine providing all operations, such as
//	- AD: Provide associated data
//	- KEY: Provide cipher key
//	- CLR: Send or receive cleartext data
//	- ENC: Send or receive encrypted data
//	- MAC: Send or receive message authentication code
//	- PRF: Extract hash / pseudorandom data
//	- RATCHET: Prevent rollback
//
// STROBE follows a little-endian convention.
type Strobe struct {
	curFlags    Flag
	initialized bool
	// i0 describes the role of this party in the protocol. The role begins as Undecided, and stays
	// that way until the party either sends or receives a message on the transport. At that point
	// the party's role becomes initiator (with i0 = Initiator) if it sent the message, or responder
	// (i0 = Responder) if it received the message.
	//
	// The purpose of i0 is to keep protocol transcripts consistent. Strobe hashes not only the
	// messages that are sent, but also metadata about who sent them. It would be no good if Alice
	// hashed "I sent a message" and Bob hashed "I received a message", because their hashes would be
	// different. Instead, they hash metadata amounting to "The initiator sent this message" or "the
	// responder sent this message.
	i0 Role
	// 0<=pos<=r, the position in the duplex state where the next byte will be processed
	pos int
	// 0<=posBegin<=r, the position in the duplex state which is 1 after the beginning of the current
	// operation, or 0 if no operation began in this block.
	posBegin int
	// r=sha3.StateLen-(2*SecurityLevel)/8-2
	r int
	// A duplex state as an array of N=sha3.StateLen bytes.
	st []byte

	keccakState [sha3.StateLen / 8]uint64
}

// AD adds associated data to the state. This data must be known to both parties, and will not be
// transmitted. Future outputs from the Strobe object will depend on the supplied data.
// If opts.Meta is set, the data will be used to describes the protocol's interpretation of the
// following operation.
// All Strobe protocols must begin with an AD operation containing a domain separation string.
func (s *Strobe) AD(data []byte, opts *Options) error {
	flag := FlagA
	if opts.Meta {
		flag |= FlagM
	}

	_, err := s.operate(flag, data, opts.Streaming)
	return err
}

// Clone returns a deeply cloned STROBE instance.
func (s *Strobe) Clone() *Strobe {
	out := &Strobe{
		curFlags:    s.curFlags,
		initialized: s.initialized,
		i0:          s.i0,
		pos:         s.pos,
		posBegin:    s.posBegin,
		r:           s.r,
		st:          append([]byte{}, s.st...),
		keccakState: s.keccakState,
	}

	return out
}

// KEY sets a symmetric key. If there is already a key, the new key will be cryptographically
// combined with it. This key will be used to produce all future cryptographic outputs from the
// STROBE object.
//
// Every crypto operation in Strobe depends on a running hash of all data which has been entered
// into it. As a result, the KEY operation has very similar semantics to AD. Both of them absorb
// data without transmitting it, and affect all future operations. That said, KEY differs from AD
// in three ways:
//
// - KEY ratchets the state to preserve forward secrecy. It does this by overwriting state bytes
// with the new key instead of xoring. This mitigates attacks if an attacker somehow compromises
// the application later. Strobe doesn't do this with most other operations, such as AD, because
// it would slightly reduce the entropy of the state.
//
// - KEY starts a new block internally (@sammyne Does this mean streaming isn't supported?). This
// is needed for ratcheting, and might also help with a future security analysis in the standard
// model.
//
// - Future authors might want to incorporate some of Strobe's operations into their protocol
// frameworks. If those frameworks don't use sponges, they will need to handle KEY differently
// from AD.
func (s *Strobe) KEY(key []byte, streaming bool) error {
	_, err := s.operate(FlagA|FlagC, key, streaming)
	return err
}

// PRF extracts hash / pseudorandom data of the given length.
func (s *Strobe) PRF(dst []byte) error {
	return s.output(FlagI|FlagA|FlagC, false, dst)
}

// RATCHET serves to prevent rollback.
func (s *Strobe) RATCHET(length int) error {
	zeros := make([]byte, length)
	return s.output(FlagC, false, zeros)
}

// RecvCLR receives a message in clear text.
// RecvCLR don't verify the integrity of the incoming message. For this, follow SendCLR with
// SendMAC on the sending side, and follow RecvCLR with RecvMAC on the receiving side.
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

// SendCLR sends a message in clear text.
// If opts.Meta is set, the data serves for framing, such as specifying message type and length
// before sending the actual message.
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

func (s *Strobe) SendMAC(dst []byte, opts *Options) error {
	flag := FlagC | FlagT
	if opts.Meta {
		flag |= FlagM
	}

	return s.output(flag, opts.Streaming, dst)
}

// New constructs a customized STROBE engine.
// @param proto serves for customization, personalization, domain separation or diversification.
// @note Only KeccakF1600 is supported for now
func New(proto string, level SecurityLevel) (*Strobe, error) {
	if level != Bit128 && level != Bit256 {
		return nil, ErrInvalidSecurityLevel
	}

	out := &Strobe{
		i0:       Undecided,
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
