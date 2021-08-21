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
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/cosmos/go-bip39"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/tendermint/tendermint/crypto/ed25519"
	"github.com/timechain.games/pillbox/util"
)

const (
	mnemonicEntropySize = 256
	// DerivationPath is the root in a BIP44 hdwallet
	DerivationPath string = "m/44'/501'/0'/0/%d"
	// Empty is the empty string
	Separator string = " "
	Empty     string = ""
	// Utf8Encoding is utf
	Utf8Encoding string = "utf8"
	// HexEncoding is hex
	HexEncoding string = "hex"
)

type AccountJSON struct {
	Mnemonic   string          `json:"mnemonic"`
	Inclusions []string        `json:"inclusions"`
	Exclusions []string        `json:"exclusions"`
	PrivateKey ed25519.PrivKey `json:"private-key"`
}

func accountPaths(b *PluginBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: QualifiedPath("accounts/?"),
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ListOperation: b.pathAccountsList,
			},
			HelpSynopsis: "List all the Solana accounts at a path",
			HelpDescription: `
			All the Solana accounts will be listed.
			`,
		},
		{
			Pattern: QualifiedPath("accounts/" + framework.GenericNameRegex("name")),
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation:   b.pathAccountsRead,
				logical.UpdateOperation: b.pathAccountUpdate,
				logical.DeleteOperation: b.pathAccountsDelete,
			},
			HelpSynopsis: "Create and read accounts.",
			HelpDescription: `
			Create and read accounts.
			`,
			Fields: map[string]*framework.FieldSchema{
				"name": {Type: framework.TypeString},
				"mnemonic": {
					Type:        framework.TypeString,
					Default:     Empty,
					Description: "The mnemonic to use to create the account. If not provided, one is generated.",
				},
				"inclusions": {
					Type:        framework.TypeCommaStringSlice,
					Description: "Only these accounts may be transaction with",
				},
				"exclusions": {
					Type:        framework.TypeCommaStringSlice,
					Description: "These accounts can never be transacted with",
				},
			},
		},
		{
			Pattern: QualifiedPath("accounts/"+framework.GenericNameRegex("name")) + "/sign",
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathAccountsSign,
			},
			HelpSynopsis: "Sign base64 encoded data.",
			HelpDescription: `
			Sign base64 encoded data.
			`,
			Fields: map[string]*framework.FieldSchema{
				"name": {Type: framework.TypeString},
				"data": {
					Type:        framework.TypeString,
					Default:     Empty,
					Description: "The data (base64 encoded) to sign.",
				},
			},
		},
	}
}

func (b *PluginBackend) updateAccount(ctx context.Context, req *logical.Request, name string, accountJSON *AccountJSON) error {
	path := QualifiedPath(fmt.Sprintf("accounts/%s", name))

	entry, err := logical.StorageEntryJSON(path, accountJSON)
	if err != nil {
		return err
	}

	err = req.Storage.Put(ctx, entry)
	if err != nil {
		return err
	}
	return nil
}

func (b *PluginBackend) pathAccountsList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	vals, err := req.Storage.List(ctx, QualifiedPath("accounts/"))
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(vals), nil
}
func readAccount(ctx context.Context, req *logical.Request, name string) (*AccountJSON, error) {
	path := QualifiedPath(fmt.Sprintf("accounts/%s", name))
	entry, err := req.Storage.Get(ctx, path)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var accountJSON AccountJSON
	err = entry.DecodeJSON(&accountJSON)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, fmt.Errorf("failed to deserialize account at %s", path)
	}
	return &accountJSON, nil
}

func (b *PluginBackend) pathAccountsRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	_, err := b.configured(ctx, req)
	if err != nil {
		return nil, err
	}
	name := data.Get("name").(string)
	accountJSON, err := readAccount(ctx, req, name)
	if err != nil {
		return nil, err
	}
	if err != nil || accountJSON == nil {
		return nil, fmt.Errorf("error reading account")
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"address":    accountJSON.PrivateKey.PubKey().Address(),
			"inclusions": accountJSON.Inclusions,
			"exclusions": accountJSON.Exclusions,
		},
	}, nil
}

func (b *PluginBackend) pathAccountsDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	_, err := b.configured(ctx, req)
	if err != nil {
		return nil, err
	}
	name := data.Get("name").(string)
	_, err = readAccount(ctx, req, name)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Delete(ctx, req.Path); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *PluginBackend) pathAccountUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	_, err := b.configured(ctx, req)
	if err != nil {
		return nil, err
	}
	isNew := false
	name := data.Get("name").(string)
	mnemonic := data.Get("mnemonic").(string)
	var inclusions []string
	if inclusionsRaw, ok := data.GetOk("inclusions"); ok {
		inclusions = inclusionsRaw.([]string)
	}
	var exclusions []string
	if exclusionsRaw, ok := data.GetOk("exclusions"); ok {
		exclusions = exclusionsRaw.([]string)
	}
	accountJSON, err := readAccount(ctx, req, name)
	if err != nil {
		return nil, err
	}
	if accountJSON == nil {
		isNew = true
		accountJSON = &AccountJSON{}
		if mnemonic == Empty {
			entropySeed, err := bip39.NewEntropy(mnemonicEntropySize)
			if err != nil {
				return nil, err
			}
			mnemonic, err = bip39.NewMnemonic(entropySeed)
			if err != nil {
				return nil, err
			}
		} else {
			mnemonic = strings.Trim(mnemonic, Separator)
		}
		accountJSON.PrivateKey = ed25519.GenPrivKeyFromSecret([]byte(mnemonic))
		accountJSON.Mnemonic = mnemonic
		if err != nil {
			return nil, err
		}
	}

	accountJSON.Inclusions = util.Dedup(inclusions)
	accountJSON.Exclusions = util.Dedup(exclusions)

	err = b.updateAccount(ctx, req, name, accountJSON)
	if err != nil {
		return nil, err
	}

	if isNew {
		return &logical.Response{
			Data: map[string]interface{}{
				"address":    accountJSON.PrivateKey.PubKey().Address(),
				"mnemonic":   accountJSON.Mnemonic,
				"inclusions": accountJSON.Inclusions,
				"exclusions": accountJSON.Exclusions,
			},
		}, nil
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"address":    accountJSON.PrivateKey.PubKey().Address(),
			"inclusions": accountJSON.Inclusions,
			"exclusions": accountJSON.Exclusions,
		},
	}, nil

}

func (b *PluginBackend) pathAccountsSign(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	_, err := b.configured(ctx, req)
	if err != nil {
		return nil, err
	}
	name := data.Get("name").(string)
	encodedData := data.Get("data").(string)

	accountJSON, err := readAccount(ctx, req, name)
	if err != nil || accountJSON == nil {
		return nil, err
	}

	decodedData, err := base64.StdEncoding.DecodeString(encodedData)
	if err != nil {
		return nil, err
	}

	signedData, err := accountJSON.PrivateKey.Sign(decodedData)
	if err != nil {
		return nil, err
	}
	encodedSignedData := base64.StdEncoding.EncodeToString(signedData)
	return &logical.Response{
		Data: map[string]interface{}{
			"address": accountJSON.PrivateKey.PubKey().Address(),
			"signed":  encodedSignedData,
		},
	}, nil

}
