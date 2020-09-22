package strobe

// The behavior of each of Strobe's operations is defined completely by 6 features, called flags. The operation is encoded as one byte, where the least significant 6 bits are its flags.
type Flag uint8

type Role uint8

type SecurityLevel int

// - I = 1<<0, "inbound". If set, this flag means that the operation moves data from the transport, to the cipher, to the application. An operation without the I flag set is said to be "outbound". The I flag is clear on all send operations, and set on all recv operations.
// - A = 1<<1, "application". If set, this flag means that the operation has data coming to or from the application side.
// 		- An operation with I and A both set outputs bytes to the application.
// 		- An operation with A set but I clear takes input from the application.
// - C = 1<<2, "cipher". If set, this flag means that the operation's output depends cryptographically on the Strobe cipher state. For operations which don't have I or T flags set, neither party produces output with this operation. In that case, the C flag instead means that the operation acts as a rekey or ratchet.
// - T = 1<<3, "transport". If set, this flag means that the operation sends or receives data using the transport. An operation has T set if and only if it has send or recv in its name.
// 		- An operation with I and T both set receives data from the transport.
// 		- An operation with T set but I clear sends data to the transport.
// - M = 1<<4, "meta". If set, this flag means that the operation is handling framing, transcript comments or some other sort of protocol metadata. It doesn't affect how the operation is performed. This is intended to be used as described below in Section 6.3.
// - K = 1<<5, "keytree". This flag is reserved for a certain protocol-level countermeasure against side-channel analysis. It does affect how an operation is performed. This specification does not describe its use. For all operations in this specification, the K flag must be clear.
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

const MagicASCII = "STROBEv1.0.2"

const (
	None      Role = 0
	Initiator Role = 1 << (iota - 1)
	Responder
)

const (
	Bit128 SecurityLevel = 128
	Bit256 SecurityLevel = 256
)
