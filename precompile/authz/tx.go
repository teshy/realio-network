package authz

import (
	"fmt"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

// GrantGenericEVM handles the grant of a generic authz authorization from the
// caller to a grantee.
func (p Precompile) GrantGenericEVM(
	ctx sdk.Context,
	origin common.Address,
	method *abi.Method,
	args []interface{},
) ([]byte, error) {
	msg, err := NewGrantGenericRequest(origin, args)
	if err != nil {
		return nil, err
	}

	// Execute grant using the authz keeper msgServer.
	_, err = p.authzKeeper.Grant(ctx, msg)
	if err != nil {
		return nil, fmt.Errorf("authz grant failed: %v", err)
	}

	// Return success
	return method.Outputs.Pack(true)
}

// GrantStakeEVM handles the grant of a staking authz authorization (restricted
// to an allow-list of validators) from the caller to a grantee.
func (p Precompile) GrantStakeEVM(
	ctx sdk.Context,
	origin common.Address,
	method *abi.Method,
	args []interface{},
) ([]byte, error) {
	msg, err := NewGrantStakeRequest(origin, args)
	if err != nil {
		return nil, err
	}

	// Execute grant using the authz keeper msgServer.
	_, err = p.authzKeeper.Grant(ctx, msg)
	if err != nil {
		return nil, fmt.Errorf("authz grant failed: %v", err)
	}

	// Return success
	return method.Outputs.Pack(true)
}

// RevokeEVM handles the revocation of an authz authorization from the caller to
// a grantee.
func (p Precompile) RevokeEVM(
	ctx sdk.Context,
	origin common.Address,
	method *abi.Method,
	args []interface{},
) ([]byte, error) {
	msg, err := NewRevokeRequest(origin, args)
	if err != nil {
		return nil, err
	}

	// Execute revoke using the authz keeper msgServer.
	_, err = p.authzKeeper.Revoke(ctx, msg)
	if err != nil {
		return nil, fmt.Errorf("authz revoke failed: %v", err)
	}

	// Return success
	return method.Outputs.Pack(true)
}
