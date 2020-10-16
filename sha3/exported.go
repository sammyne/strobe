package sha3

// StateLen is the size of keccak state in bytes.
const StateLen = 1600 / 8

// KeccakF1600 serves to export the unexported keccakF1600 so as to keep the borrowed source files
// unchanged.
func KeccakF1600(a *[25]uint64) {
	keccakF1600(a)
}
