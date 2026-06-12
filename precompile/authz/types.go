// Copyright Tharsis Labs Ltd.(Evmos)
// SPDX-License-Identifier:ENCL-1.0(https://github.com/evmos/evmos/blob/main/LICENSE)

package authz

import (
	"fmt"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"

	cmn "github.com/cosmos/evm/precompiles/common"

	sdk "github.com/cosmos/cosmos-sdk/types"
	authz "github.com/cosmos/cosmos-sdk/x/authz"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
)

const (
	AuthzPrecompileAddress = "0x0000000000000000000000000000000000000902"
	// Transactions
	GrantGenericMethod = "grantGeneric"
	GrantStakeMethod   = "grantStake"
	RevokeMethod       = "revoke"
)

// NewGrantGenericRequest parses ABI arguments and builds a MsgGrant carrying a
// GenericAuthorization for the given message type URL.
// The granter is ALWAYS bound to origin (the EVM caller), never taken from args.
// args: [grantee address, msgTypeUrl string, expiration int64]
func NewGrantGenericRequest(origin common.Address, args []interface{}) (*authz.MsgGrant, error) {
	if len(args) != 3 {
		return nil, fmt.Errorf(cmn.ErrInvalidNumberOfArgs, 3, len(args))
	}

	granteeAddr, ok := args[0].(common.Address)
	if !ok || granteeAddr == (common.Address{}) {
		return nil, fmt.Errorf(cmn.ErrInvalidHexAddress, args[0])
	}

	msgTypeURL, ok := args[1].(string)
	if !ok {
		return nil, fmt.Errorf(cmn.ErrInvalidType, "msgTypeUrl", "string", args[1])
	}

	expiration, ok := args[2].(int64)
	if !ok {
		return nil, fmt.Errorf(cmn.ErrInvalidType, "expiration", "int64", args[2])
	}

	auth := authz.NewGenericAuthorization(msgTypeURL)

	var exp *time.Time
	if expiration > 0 {
		t := time.Unix(expiration, 0).UTC()
		exp = &t
	}

	granter := sdk.AccAddress(origin.Bytes())
	grantee := sdk.AccAddress(granteeAddr.Bytes())

	return authz.NewMsgGrant(granter, grantee, auth, exp)
}

// NewGrantStakeRequest parses ABI arguments and builds a MsgGrant carrying a
// StakeAuthorization restricted to the supplied allow-list of validators.
// The granter is ALWAYS bound to origin (the EVM caller), never taken from args.
// args: [grantee address, allowedValidators []string, authorizationType string, expiration int64]
func NewGrantStakeRequest(origin common.Address, args []interface{}) (*authz.MsgGrant, error) {
	if len(args) != 4 {
		return nil, fmt.Errorf(cmn.ErrInvalidNumberOfArgs, 4, len(args))
	}

	granteeAddr, ok := args[0].(common.Address)
	if !ok || granteeAddr == (common.Address{}) {
		return nil, fmt.Errorf(cmn.ErrInvalidHexAddress, args[0])
	}

	allowedValidators, ok := args[1].([]string)
	if !ok {
		return nil, fmt.Errorf(cmn.ErrInvalidType, "allowedValidators", "[]string", args[1])
	}

	authorizationType, ok := args[2].(string)
	if !ok {
		return nil, fmt.Errorf(cmn.ErrInvalidType, "authorizationType", "string", args[2])
	}

	expiration, ok := args[3].(int64)
	if !ok {
		return nil, fmt.Errorf(cmn.ErrInvalidType, "expiration", "int64", args[3])
	}

	var authzType stakingtypes.AuthorizationType
	switch strings.ToLower(authorizationType) {
	case "delegate":
		authzType = stakingtypes.AuthorizationType_AUTHORIZATION_TYPE_DELEGATE
	case "undelegate":
		authzType = stakingtypes.AuthorizationType_AUTHORIZATION_TYPE_UNDELEGATE
	case "redelegate":
		authzType = stakingtypes.AuthorizationType_AUTHORIZATION_TYPE_REDELEGATE
	default:
		return nil, fmt.Errorf("invalid authorizationType %q: must be one of delegate, undelegate, redelegate", authorizationType)
	}

	allowList := make([]sdk.ValAddress, len(allowedValidators))
	for i, v := range allowedValidators {
		valAddr, err := sdk.ValAddressFromBech32(v)
		if err != nil {
			return nil, fmt.Errorf("invalid validator address %q: %v", v, err)
		}
		allowList[i] = valAddr
	}

	stakeAuth, err := stakingtypes.NewStakeAuthorization(allowList, nil, authzType, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create stake authorization: %v", err)
	}

	var exp *time.Time
	if expiration > 0 {
		t := time.Unix(expiration, 0).UTC()
		exp = &t
	}

	granter := sdk.AccAddress(origin.Bytes())
	grantee := sdk.AccAddress(granteeAddr.Bytes())

	return authz.NewMsgGrant(granter, grantee, stakeAuth, exp)
}

// NewRevokeRequest parses ABI arguments and builds a MsgRevoke directly.
// The granter is ALWAYS bound to origin (the EVM caller), never taken from args.
// args: [grantee address, msgTypeUrl string]
func NewRevokeRequest(origin common.Address, args []interface{}) (*authz.MsgRevoke, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf(cmn.ErrInvalidNumberOfArgs, 2, len(args))
	}

	granteeAddr, ok := args[0].(common.Address)
	if !ok || granteeAddr == (common.Address{}) {
		return nil, fmt.Errorf(cmn.ErrInvalidHexAddress, args[0])
	}

	msgTypeURL, ok := args[1].(string)
	if !ok {
		return nil, fmt.Errorf(cmn.ErrInvalidType, "msgTypeUrl", "string", args[1])
	}

	return &authz.MsgRevoke{
		Granter:    sdk.AccAddress(origin.Bytes()).String(),
		Grantee:    sdk.AccAddress(granteeAddr.Bytes()).String(),
		MsgTypeUrl: msgTypeURL,
	}, nil
}
