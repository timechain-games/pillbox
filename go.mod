module github.com/timechain.games/pillbox

go 1.16

require (
	github.com/armon/go-metrics v0.3.8 // indirect
	github.com/cosmos/go-bip39 v1.0.0
	github.com/ethereum/go-ethereum v1.10.6
	github.com/gagliardetto/solana-go v1.0.0
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/hashicorp/vault/api v1.1.1
	github.com/hashicorp/vault/sdk v0.2.1
	github.com/mitchellh/mapstructure v1.3.3 // indirect
	github.com/stretchr/objx v0.2.0 // indirect
	github.com/tendermint/tendermint v0.34.11
	github.com/timechain-games/pillbox v0.0.0-20210515145007-8f48169333ff
	google.golang.org/genproto v0.0.0-20210114201628-6edceaf6022f // indirect

)

replace google.golang.org/grpc => google.golang.org/grpc v1.33.2

replace github.com/gogo/protobuf => github.com/regen-network/protobuf v1.3.3-alpha.regen.1

replace github.com/99designs/keyring => github.com/cosmos/keyring v1.1.7-0.20210622111912-ef00f8ac3d76
