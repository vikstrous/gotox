GO15VENDOREXPERIMENT=1

.PHONY: test utils

all: utils

test:
	go test ./...

utils: utils/dht_test

utils/dht_test:
	go build -o utils/dhttest utils/dhttest.go
