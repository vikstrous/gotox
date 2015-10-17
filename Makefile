GO15VENDOREXPERIMENT=1

.PHONY: test utils bin/dhttest bin/scan

all: utils

test:
	go test ./...

utils: bin/dhttest bin/scan

bin/dhttest: dht/ utils/dhttest
	go install ./utils/dhttest/

bin/scan: dht/ utils/scan
	go install ./utils/scan/
