package sha3

const StateLen = 1600 / 8

func KeccakF1600(a *[25]uint64) {
	keccakF1600(a)
}
