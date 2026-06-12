// Copyright Tharsis Labs Ltd.(Evmos)
// SPDX-License-Identifier:ENCL-1.0(https://github.com/evmos/evmos/blob/main/LICENSE)

package authz

import (
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/x/authz"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"

	cmdconfig "github.com/realiotech/realio-network/cmd/config"
)

// TestMain configures the global sdk bech32 prefixes to "realio"/"realiovaloper"
// so that address strings render with the chain's prefixes during assertions.
// sdk.Config can only be sealed/set once per process, so we do it here.
func TestMain(m *testing.M) {
	config := sdk.GetConfig()
	cmdconfig.SetBech32Prefixes(config)
	// NOTE: intentionally NOT sealing the config — sealing would break other
	// tests in the package if added later. Setting the prefixes is sufficient
	// for address rendering in these pure unit tests.
	m.Run()
}

// Fixed test fixtures. These are arbitrary but stable 20-byte EVM addresses.
var (
	// originAddr is the EVM caller; its bytes derive the granter.
	originAddr = common.HexToAddress("0x1111111111111111111111111111111111111111")
	// granteeAddr is passed as an ABI arg.
	granteeAddr = common.HexToAddress("0x2222222222222222222222222222222222222222")
)

// expectedGranter returns the bech32 the granter MUST equal — derived from
// origin's bytes, never from any ABI arg.
func expectedGranter() string {
	return sdk.AccAddress(originAddr.Bytes()).String()
}

func expectedGrantee() string {
	return sdk.AccAddress(granteeAddr.Bytes()).String()
}

// validValoper returns a bech32 valoper address derived from arbitrary bytes,
// using the realiovaloper prefix configured in TestMain.
func validValoper(b byte) string {
	bz := make([]byte, 20)
	for i := range bz {
		bz[i] = b
	}
	return sdk.ValAddress(bz).String()
}

// ---------------------------------------------------------------------------
// 1. Granter binding — security-critical: granter ALWAYS derives from origin.
// ---------------------------------------------------------------------------

func TestGranterAlwaysBoundToOrigin(t *testing.T) {
	want := expectedGranter()

	t.Run("grantGeneric", func(t *testing.T) {
		msg, err := NewGrantGenericRequest(originAddr, []interface{}{
			granteeAddr,
			"/cosmos.bank.v1beta1.MsgSend",
			int64(0),
		})
		require.NoError(t, err)
		require.Equal(t, want, msg.Granter)
		// The granter must NOT equal the grantee (no arg leakage).
		require.NotEqual(t, msg.Grantee, msg.Granter)
	})

	t.Run("grantStake", func(t *testing.T) {
		msg, err := NewGrantStakeRequest(originAddr, []interface{}{
			granteeAddr,
			[]string{validValoper(0x03)},
			"delegate",
			int64(0),
		})
		require.NoError(t, err)
		require.Equal(t, want, msg.Granter)
		require.NotEqual(t, msg.Grantee, msg.Granter)
	})

	t.Run("revoke", func(t *testing.T) {
		msg, err := NewRevokeRequest(originAddr, []interface{}{
			granteeAddr,
			"/cosmos.bank.v1beta1.MsgSend",
		})
		require.NoError(t, err)
		require.Equal(t, want, msg.Granter)
		require.NotEqual(t, msg.Grantee, msg.Granter)
	})
}

// ---------------------------------------------------------------------------
// 2. grantGeneric happy path.
// ---------------------------------------------------------------------------

func TestNewGrantGenericRequest_HappyPath(t *testing.T) {
	const msgType = "/cosmos.staking.v1beta1.MsgDelegate"

	t.Run("no expiration (0) leaves Expiration nil", func(t *testing.T) {
		msg, err := NewGrantGenericRequest(originAddr, []interface{}{
			granteeAddr,
			msgType,
			int64(0),
		})
		require.NoError(t, err)

		require.Equal(t, expectedGranter(), msg.Granter)
		require.Equal(t, expectedGrantee(), msg.Grantee)
		require.Nil(t, msg.Grant.Expiration)

		auth, err := msg.GetAuthorization()
		require.NoError(t, err)
		gen, ok := auth.(*authz.GenericAuthorization)
		require.True(t, ok, "authorization should be a *GenericAuthorization, got %T", auth)
		require.Equal(t, msgType, gen.Msg)
		require.Equal(t, msgType, gen.MsgTypeURL())
	})

	t.Run("positive expiration sets the time (UTC)", func(t *testing.T) {
		const exp = int64(1893456000) // 2030-01-01T00:00:00Z
		msg, err := NewGrantGenericRequest(originAddr, []interface{}{
			granteeAddr,
			msgType,
			exp,
		})
		require.NoError(t, err)

		require.NotNil(t, msg.Grant.Expiration)
		wantTime := time.Unix(exp, 0).UTC()
		require.True(t, msg.Grant.Expiration.Equal(wantTime),
			"expiration = %v, want %v", msg.Grant.Expiration, wantTime)
	})
}

// ---------------------------------------------------------------------------
// 3. grantStake happy path + authzType mapping + valoper validation.
// ---------------------------------------------------------------------------

func TestNewGrantStakeRequest_AuthzTypeMapping(t *testing.T) {
	valopers := []string{validValoper(0x0a), validValoper(0x0b)}

	cases := []struct {
		name     string
		input    string
		wantType stakingtypes.AuthorizationType
	}{
		{"delegate lower", "delegate", stakingtypes.AuthorizationType_AUTHORIZATION_TYPE_DELEGATE},
		{"undelegate lower", "undelegate", stakingtypes.AuthorizationType_AUTHORIZATION_TYPE_UNDELEGATE},
		{"redelegate lower", "redelegate", stakingtypes.AuthorizationType_AUTHORIZATION_TYPE_REDELEGATE},
		// case-insensitive: impl uses strings.ToLower.
		{"DELEGATE upper", "DELEGATE", stakingtypes.AuthorizationType_AUTHORIZATION_TYPE_DELEGATE},
		{"ReDeLeGaTe mixed", "ReDeLeGaTe", stakingtypes.AuthorizationType_AUTHORIZATION_TYPE_REDELEGATE},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg, err := NewGrantStakeRequest(originAddr, []interface{}{
				granteeAddr,
				valopers,
				tc.input,
				int64(0),
			})
			require.NoError(t, err)

			require.Equal(t, expectedGranter(), msg.Granter)
			require.Equal(t, expectedGrantee(), msg.Grantee)

			auth, err := msg.GetAuthorization()
			require.NoError(t, err)
			stakeAuth, ok := auth.(*stakingtypes.StakeAuthorization)
			require.True(t, ok, "authorization should be a *StakeAuthorization, got %T", auth)

			require.Equal(t, tc.wantType, stakeAuth.AuthorizationType)

			allow := stakeAuth.GetAllowList()
			require.NotNil(t, allow, "allow-list should be set (not deny-list)")
			require.Nil(t, stakeAuth.GetDenyList())
			require.Equal(t, valopers, allow.GetAddress())
			// MaxTokens passed as nil in the builder.
			require.Nil(t, stakeAuth.MaxTokens)
		})
	}
}

func TestNewGrantStakeRequest_Errors(t *testing.T) {
	validVals := []string{validValoper(0x0c)}

	t.Run("invalid authorizationType", func(t *testing.T) {
		_, err := NewGrantStakeRequest(originAddr, []interface{}{
			granteeAddr,
			validVals,
			"vote", // not a staking authz type
			int64(0),
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid authorizationType")
	})

	t.Run("invalid valoper bech32", func(t *testing.T) {
		_, err := NewGrantStakeRequest(originAddr, []interface{}{
			granteeAddr,
			[]string{"not-a-valoper"},
			"delegate",
			int64(0),
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid validator address")
	})

	t.Run("account-prefixed address rejected as valoper", func(t *testing.T) {
		// A realio1... account address is not a valid realiovaloper1... address.
		_, err := NewGrantStakeRequest(originAddr, []interface{}{
			granteeAddr,
			[]string{expectedGrantee()},
			"delegate",
			int64(0),
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid validator address")
	})
}

func TestNewGrantStakeRequest_Expiration(t *testing.T) {
	const exp = int64(1893456000)
	msg, err := NewGrantStakeRequest(originAddr, []interface{}{
		granteeAddr,
		[]string{validValoper(0x0d)},
		"delegate",
		exp,
	})
	require.NoError(t, err)
	require.NotNil(t, msg.Grant.Expiration)
	require.True(t, msg.Grant.Expiration.Equal(time.Unix(exp, 0).UTC()))
}

// ---------------------------------------------------------------------------
// 4. revoke happy path.
// ---------------------------------------------------------------------------

func TestNewRevokeRequest_HappyPath(t *testing.T) {
	const msgType = "/cosmos.staking.v1beta1.MsgDelegate"
	msg, err := NewRevokeRequest(originAddr, []interface{}{
		granteeAddr,
		msgType,
	})
	require.NoError(t, err)
	require.Equal(t, expectedGranter(), msg.Granter)
	require.Equal(t, expectedGrantee(), msg.Grantee)
	require.Equal(t, msgType, msg.MsgTypeUrl)
}

// ---------------------------------------------------------------------------
// 5. Error cases shared across builders: arg count, arg types, zero grantee.
// ---------------------------------------------------------------------------

func TestNewGrantGenericRequest_ArgErrors(t *testing.T) {
	cases := []struct {
		name string
		args []interface{}
	}{
		{"too few args", []interface{}{granteeAddr, "/x"}},
		{"too many args", []interface{}{granteeAddr, "/x", int64(0), "extra"}},
		{"grantee not an address", []interface{}{"0xdeadbeef", "/x", int64(0)}},
		{"zero grantee address", []interface{}{common.Address{}, "/x", int64(0)}},
		{"msgTypeUrl not a string", []interface{}{granteeAddr, 123, int64(0)}},
		{"expiration not int64", []interface{}{granteeAddr, "/x", "soon"}},
		{"expiration is int (not int64)", []interface{}{granteeAddr, "/x", 0}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewGrantGenericRequest(originAddr, tc.args)
			require.Error(t, err)
		})
	}
}

func TestNewGrantStakeRequest_ArgErrors(t *testing.T) {
	vals := []string{validValoper(0x0e)}
	cases := []struct {
		name string
		args []interface{}
	}{
		{"too few args", []interface{}{granteeAddr, vals, "delegate"}},
		{"too many args", []interface{}{granteeAddr, vals, "delegate", int64(0), "x"}},
		{"grantee not an address", []interface{}{"0xabc", vals, "delegate", int64(0)}},
		{"zero grantee address", []interface{}{common.Address{}, vals, "delegate", int64(0)}},
		{"validators not []string", []interface{}{granteeAddr, "single-string", "delegate", int64(0)}},
		{"authorizationType not a string", []interface{}{granteeAddr, vals, 7, int64(0)}},
		{"expiration not int64", []interface{}{granteeAddr, vals, "delegate", "later"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewGrantStakeRequest(originAddr, tc.args)
			require.Error(t, err)
		})
	}
}

func TestNewRevokeRequest_ArgErrors(t *testing.T) {
	cases := []struct {
		name string
		args []interface{}
	}{
		{"too few args", []interface{}{granteeAddr}},
		{"too many args", []interface{}{granteeAddr, "/x", "extra"}},
		{"grantee not an address", []interface{}{"0xabc", "/x"}},
		{"zero grantee address", []interface{}{common.Address{}, "/x"}},
		{"msgTypeUrl not a string", []interface{}{granteeAddr, 99}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewRevokeRequest(originAddr, tc.args)
			require.Error(t, err)
		})
	}
}

// ---------------------------------------------------------------------------
// 6. IsTransaction — method-name classification.
//
// IsTransaction takes an *abi.Method and switches purely on method.Name, so we
// can exercise it via a real Precompile built from the embedded ABI without a
// keeper: NewPrecompile only needs codec/keeper/addrCodec to *store*, and the
// method lookup comes from the loaded ABI. We avoid constructing a keeper by
// loading the ABI directly and resolving methods from it.
// ---------------------------------------------------------------------------

func TestIsTransaction(t *testing.T) {
	abiObj, err := LoadABI()
	require.NoError(t, err)

	// Precompile.IsTransaction has a value receiver and no dependencies, so a
	// zero-value Precompile is sufficient to call it.
	var p Precompile

	for _, name := range []string{GrantGenericMethod, GrantStakeMethod, RevokeMethod} {
		method, ok := abiObj.Methods[name]
		require.True(t, ok, "ABI is missing expected method %q", name)
		require.True(t, p.IsTransaction(&method), "%q should be a transaction", name)
	}

	// Any method whose name is not one of the three transaction methods.
	for _, name := range abiObj.Methods {
		if name.Name == GrantGenericMethod || name.Name == GrantStakeMethod || name.Name == RevokeMethod {
			continue
		}
		nonTx := name
		require.False(t, p.IsTransaction(&nonTx), "%q should NOT be a transaction", name.Name)
	}

	// Synthetic unknown method name is also not a transaction.
	unknown := abi.Method{Name: "totallyUnknownMethod"}
	require.False(t, p.IsTransaction(&unknown))
}
