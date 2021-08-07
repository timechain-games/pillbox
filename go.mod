module github.com/timechain.games/pillbox

go 1.16

require (
	github.com/cosmos/cosmos-sdk v0.42.9
	github.com/ethereum/go-ethereum v1.10.6
	github.com/hashicorp/errwrap v1.1.0
	github.com/hashicorp/vault/api v1.1.1
	github.com/hashicorp/vault/sdk v0.2.1
	github.com/tendermint/tendermint v0.34.11 
	github.com/timechain-games/pillbox v0.0.0-20210515145007-8f48169333ff

)

replace google.golang.org/grpc => google.golang.org/grpc v1.33.2

replace github.com/gogo/protobuf => github.com/regen-network/protobuf v1.3.3-alpha.regen.1

replace github.com/99designs/keyring => github.com/cosmos/keyring v1.1.7-0.20210622111912-ef00f8ac3d76
