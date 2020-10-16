// package strobe implements the STROBE@v1.0.2 framework.
//
// See also the specification https://strobe.sourceforge.io/specs/.
//
// A more complex protocol might have many different meanings for the same operation.
// A natural pattern to ensure parseability is to precede each operation with a comment in the
// transcript that disambiguates it. Such information is usually provided anyway through protocol
// an operation called framing.
//
package strobe

import (
	"github.com/sammyne/strobe/sha3"
)

// Options define common options for different operations.
type Options struct {
	// Meta specifies the data to operate on is meta.
	Meta bool
	// Streaming specifies the data will be processed in a streaming fashion, one byte at a time.
	// This also means the current input data follows the previous one.
	Streaming bool
}

// Strobe implements STROBE framework, offering a sequence of operations as
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
	// r=sha3.StateLen-(2*SecurityLevel)/8-2.
	r int
	// A duplex state as an array of N=sha3.StateLen bytes.
	st []byte

	// keccakState is the transformed version of st, to adapt to the API of sha3 package.
	keccakState [sha3.StateLen / 8]uint64
}

// AD adds associated data to the state. This data must be known to both parties, and will not be
// transmitted. Future outputs from the Strobe object will depend on the supplied data.
// If opts.Meta is set, the data will be used to describes the protocol's interpretation of the
// following operation.
//
// All Strobe protocols must begin with an AD operation containing a domain separation string.
//
// @dev data WILL BE MODIFIED IN PLACED.
//
// Further reference sees <6.1.1. AD: Provide associated data>:
// https://strobe.sourceforge.io/specs/#ops.bare.ad
func (s *Strobe) AD(data []byte, opts *Options) error {
	flag := frameIf(FlagA, opts.Meta)
	_, err := s.operate(flag, data, opts.Streaming)
	return err
}

// Clone returns a DEEPLY cloned STROBE instance.
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
// @dev data WILL BE MODIFIED IN PLACED.
//
// Further reference sees <6.1.2. KEY: Provide cipher key>:
// https://strobe.sourceforge.io/specs/#ops.bare.key
func (s *Strobe) KEY(key []byte, streaming bool) error {
	_, err := s.operate(FlagA|FlagC, key, streaming)
	return err
}

// PRF extracts pseudorandom data which is a deterministic function of the state. This data can be
// treated as a hash of all preceeding operations, messages and keys.
//
// Just as with a MAC, the PRF operation supports streaming, and a shorter PRF call will return a
// prefix of a longer one.
//
// @dev data WILL BE MODIFIED IN PLACED.
//
// Further reference sees <6.1.6. PRF: Extract hash / pseudorandom data>:
// https://strobe.sourceforge.io/specs/#ops.bare.prf
func (s *Strobe) PRF(dst []byte, streaming bool) error {
	return s.output(FlagI|FlagA|FlagC, streaming, dst)
}

// RATCHET has no input other than a length, and no output. Instead, it modifies the state in an
// irreversible way.
// If meta[0] is true, then length either 0 or R is suggested as a way to forcibly align to the
// beginning of a block, which has a few niche use cases.
//
// RATCHET serves to prevent rollback.
//
// Further reference sees <6.1.7. RATCHET: Prevent rollback>:
// https://strobe.sourceforge.io/specs/#ops.bare.ratchet
func (s *Strobe) RATCHET(length int, meta ...bool) error {
	flag := FlagC
	if len(meta) > 0 && meta[0] {
		flag |= FlagM
	}

	zeros := make([]byte, length)
	return s.output(flag, false, zeros)
}

// RecvCLR receives a message in clear text.
// RecvCLR don't verify the integrity of the incoming message. For this, follow SendCLR with
// SendMAC on the sending side, and follow RecvCLR with RecvMAC on the receiving side.
//
// @dev data WILL BE MODIFIED IN PLACED.
//
// Futher reference sees <6.1.3. CLR: Send or receive cleartext data>:
// https://strobe.sourceforge.io/specs/#ops.bare.clr
func (s *Strobe) RecvCLR(data []byte, opts *Options) error {
	flag := frameIf(FlagI|FlagA|FlagT, opts.Meta)
	_, err := s.operate(flag, data, opts.Streaming)
	return err
}

// RecvENC decrypts the ciphertext received from the transport, and return the decrypted plaintext.
//
// RecvENC doesn't require uniqueness for security, so long as a RecvMAC operation is run before the received data is used.
//
// The RecvENC operations don't verify the integrity of the incoming message. For this, use
// SendMAC after SendENC on the sending side, and RecvMAC after RecvENC on the receiving side. The
// receiving side must run RecvMAC before using the decrypted message.
//
// @dev data WILL BE MODIFIED IN PLACED.
//
// Futher reference sees <6.1.4. ENC: Send or receive encrypted data>:
// https://strobe.sourceforge.io/specs/#ops.bare.enc
func (s *Strobe) RecvENC(ciphertext []byte, opts *Options) ([]byte, error) {
	flag := frameIf(FlagI|FlagA|FlagC|FlagT, opts.Meta)
	return s.operate(flag, ciphertext, opts.Streaming)
}

// RecvMAC receives and checks a MAC. If errors out, the receiving party should abort
// the protocol.
//
// This is appropriate for checking the integrity of framing data.
//
// @dev data WILL BE MODIFIED IN PLACED.
//
// As for further warning and notes, please check section 6.1.5 of the STROBE spec:
// https://strobe.sourceforge.io/specs/#ops.bare.mac .
func (s *Strobe) RecvMAC(mac []byte, opts *Options) error {
	flag := frameIf(FlagI|FlagC|FlagT, opts.Meta)
	_, err := s.operate(flag, mac, opts.Streaming)
	return err
}

// SendCLR sends a data in clear text.
//
// If opts.Meta is set, the data serves for framing, such as specifying message type and length
// before sending the actual message.
//
// The recipient should call the RecvCLR so as to synchronize the running hash state with the
// sender.
//
// @dev data WILL BE MODIFIED IN PLACED.
//
// Futher reference sees <6.1.3. CLR: Send or receive cleartext data>:
// https://strobe.sourceforge.io/specs/#ops.bare.clr
func (s *Strobe) SendCLR(data []byte, opts *Options) error {
	flag := frameIf(FlagA|FlagT, opts.Meta)
	_, err := s.operate(flag, data, opts.Streaming)
	return err
}

// SendENC encrypts the data and returns the ciphertext to send to the transport.
//
// @dev data WILL BE MODIFIED IN PLACED.
//
// Futher reference sees <6.1.4. ENC: Send or receive encrypted data>:
// https://strobe.sourceforge.io/specs/#ops.bare.enc
func (s *Strobe) SendENC(data []byte, opts *Options) ([]byte, error) {
	flag := frameIf(FlagA|FlagC|FlagT, opts.Meta)
	return s.operate(flag, data, opts.Streaming)
}

// SendMAC computes and sends a message authentication code (MAC).
//
// This is appropriate for checking the integrity of framing data.
//
// @dev data WILL BE MODIFIED IN PLACED.
//
// As for further warning and notes, please check section 6.1.5 of the STROBE spec:
// https://strobe.sourceforge.io/specs/#ops.bare.mac .
func (s *Strobe) SendMAC(dst []byte, opts *Options) error {
	flag := frameIf(FlagC|FlagT, opts.Meta)
	return s.output(flag, opts.Streaming, dst)
}

// New constructs a customized STROBE engine.
//
// proto serves for customization, personalization, domain separation or diversification.
//
// ONLY KeccakF1600 is supported for now
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

	// The spec's domain goes as
	//   st = F( [0x01, R+2, 0x01, 0x00, 0x01, 0x60] + ascii("STROBEv1.0.2"))
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
