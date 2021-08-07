// Copyright © 2021 Immutability, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"fmt"

	"github.com/cosmos/cosmos-sdk/crypto/hd"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/cidrutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/tendermint/tendermint/crypto/ed25519"
	"github.com/timechain-games/pillbox/util"
)

type Account struct {
	PrivateKey  ed25519.PrivKey
	BIP44Params hd.BIP44Params
	Algorithm   hd.PubKeyType
	Mnemonic    string
}

func Address(account *Account) string {
	return account.PrivateKey.PubKey().Address().String()
}

// ConfigJSON contains the configuration for each mount
type ConfigJSON struct {
	BoundCIDRList []string `json:"bound_cidr_list_list" structs:"bound_cidr_list" mapstructure:"bound_cidr_list"`
	Inclusions    []string `json:"inclusions"`
	Exclusions    []string `json:"exclusions"`
	RPC           string   `json:"rpc_url"`
}

// ValidAddress returns an error if the address is not included or if it is excluded
func (config *ConfigJSON) ValidAddress(toAddress string) error {

	if util.Contains(config.Exclusions, toAddress) {
		return fmt.Errorf("%s is excludeded by this mount", toAddress)
	}

	if len(config.Inclusions) > 0 && !util.Contains(config.Inclusions, toAddress) {
		return fmt.Errorf("%s is not in the set of inclusions of this mount", toAddress)
	}
	return nil
}

func configPaths(b *PluginBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "config",
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.CreateOperation: b.pathWriteConfig,
				logical.UpdateOperation: b.pathWriteConfig,
				logical.ReadOperation:   b.pathReadConfig,
			},
			HelpSynopsis: "Configure the Pillbox plugin.",
			HelpDescription: `
			Configure the Pillbox plugin.
			`,
			Fields: map[string]*framework.FieldSchema{
				"rpc_url": {
					Type:        framework.TypeString,
					Description: "The RPC address of the Solana node",
				},
				"inclusions": {
					Type:        framework.TypeCommaStringSlice,
					Description: "Only these accounts may be transaction with",
				},
				"exclusions": {
					Type:        framework.TypeCommaStringSlice,
					Description: "These accounts can never be transacted with",
				},
				"bound_cidr_list": {
					Type: framework.TypeCommaStringSlice,
					Description: `Comma separated string or list of CIDR blocks.
If set, specifies the blocks of IPs which can perform the login operation;
if unset, there are no IP restrictions.`,
				},
			},
		},
	}
}

func (config *ConfigJSON) getRPCURL() string {
	return config.RPC
}

func (b *PluginBackend) pathWriteConfig(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	rpcURL := data.Get("rpc_url").(string)
	var boundCIDRList []string
	if boundCIDRListRaw, ok := data.GetOk("bound_cidr_list"); ok {
		boundCIDRList = boundCIDRListRaw.([]string)
	}
	var inclusions []string
	if inclusionsRaw, ok := data.GetOk("inclusions"); ok {
		inclusions = inclusionsRaw.([]string)
	}
	var exclusions []string
	if exclusionsRaw, ok := data.GetOk("exclusions"); ok {
		exclusions = exclusionsRaw.([]string)
	}
	configBundle := ConfigJSON{
		BoundCIDRList: boundCIDRList,
		Inclusions:    inclusions,
		Exclusions:    exclusions,
		RPC:           rpcURL,
	}
	entry, err := logical.StorageEntryJSON("config", configBundle)

	if err != nil {

		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}
	// Return the secret
	return &logical.Response{
		Data: map[string]interface{}{
			"bound_cidr_list": configBundle.BoundCIDRList,
			"inclusions":      configBundle.Inclusions,
			"exclusions":      configBundle.Exclusions,
			"rpc_url":         configBundle.RPC,
		},
	}, nil
}

func (b *PluginBackend) pathReadConfig(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	configBundle, err := b.readConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if configBundle == nil {
		return nil, nil
	}

	// Return the secret
	return &logical.Response{
		Data: map[string]interface{}{
			"bound_cidr_list": configBundle.BoundCIDRList,
			"inclusions":      configBundle.Inclusions,
			"exclusions":      configBundle.Exclusions,
			"rpc_url":         configBundle.RPC,
		},
	}, nil
}

// Config returns the configuration for this PluginBackend.
func (b *PluginBackend) readConfig(ctx context.Context, s logical.Storage) (*ConfigJSON, error) {
	entry, err := s.Get(ctx, "config")
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, fmt.Errorf("the plugin has not been configured yet")
	}

	var result ConfigJSON
	if entry != nil {
		if err := entry.DecodeJSON(&result); err != nil {
			return nil, fmt.Errorf("error reading configuration: %s", err)
		}
	}

	return &result, nil
}

func (b *PluginBackend) configured(ctx context.Context, req *logical.Request) (*ConfigJSON, error) {
	config, err := b.readConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if validConnection, err := b.validIPConstraints(config, req); !validConnection {
		return nil, err
	}

	return config, nil
}

func (b *PluginBackend) validIPConstraints(config *ConfigJSON, req *logical.Request) (bool, error) {
	if len(config.BoundCIDRList) != 0 {
		if req.Connection == nil || req.Connection.RemoteAddr == "" {
			return false, fmt.Errorf("failed to get connection information")
		}

		belongs, err := cidrutil.IPBelongsToCIDRBlocksSlice(req.Connection.RemoteAddr, config.BoundCIDRList)
		if err != nil {
			return false, errwrap.Wrapf("failed to verify the CIDR restrictions set on the role: {{err}}", err)
		}
		if !belongs {
			return false, fmt.Errorf("source address %q unauthorized through CIDR restrictions on the role", req.Connection.RemoteAddr)
		}
	}
	return true, nil
}
