package authz

import "testing"

// TestRequiredGasShortInput guards M1 (audit docs/12): RequiredGas must not panic
// on sub-4-byte calldata. The EVM invokes RequiredGas with raw, unpadded calldata
// before Run, so a <4-byte CALL to the precompile must return 0, not slice-panic.
func TestRequiredGasShortInput(t *testing.T) {
	p, err := NewPrecompileForTest()
	if err != nil {
		t.Fatalf("NewPrecompile: %v", err)
	}
	for _, in := range [][]byte{nil, {}, {0x01}, {0x01, 0x02}, {0x01, 0x02, 0x03}} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("RequiredGas panicked on %d-byte input: %v", len(in), r)
				}
			}()
			if g := p.RequiredGas(in); g != 0 {
				t.Fatalf("RequiredGas(%d bytes) = %d, want 0", len(in), g)
			}
		}()
	}
	// 4-byte unknown selector: no panic, returns 0 (method not found).
	if g := p.RequiredGas([]byte{0xde, 0xad, 0xbe, 0xef}); g != 0 {
		t.Fatalf("RequiredGas(unknown 4-byte) = %d, want 0", g)
	}
}

// NewPrecompileForTest builds a Precompile with only the ABI loaded — enough for
// RequiredGas/IsTransaction, which don't touch the keeper.
func NewPrecompileForTest() (*Precompile, error) {
	abi, err := LoadABI()
	if err != nil {
		return nil, err
	}
	return &Precompile{ABI: abi}, nil
}
