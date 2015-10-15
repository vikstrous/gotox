GO15VENDOREXPERIMENT=1

.PHONY: test utils

all: utils

test:
	go test ./...

utils: utils/dhttest utils/scan

utils/dhttest: dht/*.go utils/dhttest.go
	go build -o utils/dhttest utils/dhttest.go

utils/scan: dht/*.go utils/scan.go
	go build -o utils/scan utils/scan.go
