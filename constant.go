package strobe

// Flag defines the behavior of each of Strobe's operations. Currently, 6 features are available.
// The operation is encoded as one byte, where the least significant 6 bits are its flags.
type Flag uint8

// Role defines roles of party involved in the protocol.
type Role uint8

// SecurityLevel defines the security level of the protocol.
type SecurityLevel int

// Currently, 6 flags are avaiable.
//
// - I = 1<<0, "inbound". If set, this flag means that the operation moves data from the transport,
// to the cipher, to the application. An operation without the I flag set is said to be "outbound".
// The I flag is clear on all send operations, and set on all recv operations.
//
// - A = 1<<1, "application". If set, this flag means that the operation has data coming to or from
// the application side.
//   - An operation with I and A both set outputs bytes to the application.
//   - An operation with A set but I clear takes input from the application.
//
// - C = 1<<2, "cipher". If set, this flag means that the operation's output depends
// cryptographically on the Strobe cipher state. For operations which don't have I or T flags set,
// neither party produces output with this operation. In that case, the C flag instead means that
// the operation acts as a rekey or ratchet.
//
// - T = 1<<3, "transport". If set, this flag means that the operation sends or receives data using
// the transport. An operation has T set if and only if it has send or recv in its name.
//   - An operation with I and T both set receives data from the transport.
//   - An operation with T set but I clear sends data to the transport.
//
// - M = 1<<4, "meta". If set, this flag means that the operation is handling framing, transcript
// comments or some other sort of protocol metadata. It doesn't affect how the operation is
// performed.
//
// - K = 1<<5, "keytree". This flag is reserved for a certain protocol-level countermeasure against
// side-channel analysis. It does affect how an operation is performed. For all operations in this
// STROBE specification, the K flag must be clear.
//
// - The flags 1<<6 and 1<<7 are reserved for future versions.
const (
	FlagNone Flag = 0
	FlagI    Flag = 1 << (iota - 1)
	FlagA
	FlagC
	FlagT
	FlagM
	FlagK
)

// MagicASCII specifies a human-readable STROBE version.
const MagicASCII = "STROBEv1.0.2"

// To disambiguate the two parties of a network protocol, STROBE assigns them each a
// role as an initiator or responder.
//
// Parties start out as undecided, and become an initiator or responder if and when they send or receive a message via the transport.
const (
	// Undecided is a party which has neither sent nor received any messages.
	Undecided Role = 0
	// Initiator is party to a protocol who sent a message to the transport before receiving any
	// messages from the transport.
	Initiator Role = 1 << (iota - 1)
	// Responder is a party to a protocol who received a message from the transport before sending
	// any messages to the transport.
	// @note Respsonder has different value from that in the spec,
	// https://strobe.sourceforge.io/specs/, which is 1.
	Responder
)

const (
	// Bit128 targets a security level of 128 bits.
	Bit128 SecurityLevel = 128
	// Bit256 targets a security level of 256 bits.
	Bit256 SecurityLevel = 256
)
