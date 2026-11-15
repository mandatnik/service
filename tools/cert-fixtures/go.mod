module mandatnik/cert-fixtures

go 1.26.3

require gost-sig v0.0.0

require (
	github.com/deatil/go-cryptobin v1.1.1021 // indirect
	golang.org/x/crypto v0.53.0 // indirect
)

replace gost-sig => ../../node_modules/gost-ca
