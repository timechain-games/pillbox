package util

import (
	"crypto/hmac"
	"crypto/sha512"
)

const ED25519_BIP32_NAME string = "ed25519 seed"

// HDWallet is a place holder
type ExtendedSecretKey struct {
	depth       int8
	child_index uint8
	chain_code  [32]byte
	secret_key  [32]byte
}

func NewExtendedSecretKey(seed []byte) *ExtendedSecretKey {
	h := hmac.New(sha512.New, []byte(ED25519_BIP32_NAME))
	h.Write([]byte(seed))
	var secret_key [32]byte
	var chain_code [32]byte
	copy(secret_key[:], h.Sum(nil))
	copy(chain_code[:], h.Sum(nil))
	extended_key := ExtendedSecretKey{
		depth:       0,
		child_index: 0,
		chain_code:  chain_code,
		secret_key:  secret_key,
	}
	return &extended_key
}

func (extendedSecretKey *ExtendedSecretKey) derive_key(index uint8) *ExtendedSecretKey {
	derivation := hmac.New(sha512.New, extendedSecretKey.chain_code[:])
	// w/e this means:  mac.update(&[0u8]);
	derivation.Write(extendedSecretKey.secret_key[:])
	// need to write index, is it this simple?
	byteses := make([]byte, 1)
	byteses[0] = index
	derivation.Write(byteses[:])
	derived_secret := ExtendedSecretKey{
		depth:       0,
		child_index: index,
	}
	copy(derived_secret.secret_key[:], derivation.Sum(nil))
	copy(derived_secret.chain_code[:], derivation.Sum(nil))
	return &derived_secret
}
