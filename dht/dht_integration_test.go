package dht

import (
	"encoding/hex"
	"net"
	//"reflect"
	"testing"
	"time"

	"github.com/vikstrous/gotox"
	"golang.org/x/crypto/nacl/box"
)

var publicKey = [gotox.PublicKeySize]byte{}

func init() {
	publicKeySlice, _ := hex.DecodeString("A4D28D52D4116A02147ECE6C6299DA3F5524DEBA043B067CF7D5BF2E09064032353CFD14B519")
	copy(publicKey[:], publicKeySlice)
}

func TestBootstrap(t *testing.T) {
	dht, err := New()
	if err != nil {
		t.Fatalf("Failed to create server %s.", err)
	}
	go dht.Serve()
	defer dht.Stop()

	dht.AddFriend(publicKey)

	// getnodes
	data, err := dht.getNodes(dhtServerList[0], publicKey)
	if err != nil {
		t.Errorf("error %s", err)
	}
	err = dht.send(data, dhtServerList[0])
	if err != nil {
		t.Errorf("error %s", err)
	}

	time.Sleep(time.Second)
	//<-dht.request
}
