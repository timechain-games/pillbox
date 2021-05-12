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

package util

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"regexp"

	"github.com/ethereum/go-ethereum/common/math"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// PrettyPrint prints an indented JSON payload. This is used for development debugging.
func PrettyPrint(v interface{}) string {
	jsonString, _ := json.Marshal(v)
	var out bytes.Buffer
	json.Indent(&out, jsonString, "", "  ")
	return out.String()
}

// Dedup removes duplicates from a list
func Dedup(stringSlice []string) []string {
	var returnSlice []string
	for _, value := range stringSlice {
		if !Contains(returnSlice, value) {
			returnSlice = append(returnSlice, value)
		}
	}
	return returnSlice
}

// Contains returns true if an element is present in a list
func Contains(stringSlice []string, searchString string) bool {
	for _, value := range stringSlice {
		if value == searchString {
			return true
		}
	}
	return false
}

// Encode will encode a raw key or seed
func Encode(src []byte) ([]byte, error) {
	buf := make([]byte, hex.EncodedLen(len(src)))
	hex.Encode(buf, src)

	return buf[:], nil
}

// Decode will decode the hex
func Decode(src []byte) ([]byte, error) {
	raw := make([]byte, hex.EncodedLen(len(src)))
	n, err := hex.Decode(raw, src)
	if err != nil {
		return nil, err
	}
	raw = raw[:n]
	return raw[:], nil
}

// SealWrapAppend is a helper for appending lists of paths into a single
// list.
func SealWrapAppend(paths ...[]string) []string {
	result := make([]string, 0, 10)
	for _, ps := range paths {
		result = append(result, ps...)
	}

	return result
}

// PathExistenceCheck checks storage for a path
func PathExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	out, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return false, fmt.Errorf("existence check failed: %v", err)
	}

	return out != nil, nil
}

// ValidNumber returns a valid positive integer
func ValidNumber(input string) *big.Int {
	if input == "" {
		return big.NewInt(0)
	}
	matched, err := regexp.MatchString("([0-9])", input)
	if !matched || err != nil {
		return nil
	}
	amount := math.MustParseBig256(input)
	return amount.Abs(amount)
}

// Pow computes a^b for int64
func Pow(a, b int64) int64 {
	var result int64 = 1

	for 0 != b {
		if 0 != (b & 1) {
			result *= a

		}
		b >>= 1
		a *= a
	}

	return result
}

// ZeroKey removes the key from memory
func ZeroKey(k *ecdsa.PrivateKey) {
	b := k.D.Bits()
	for i := range b {
		b[i] = 0
	}
}

func ensureContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.TODO()
	}
	return ctx
}
