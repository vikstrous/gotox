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

func TestPing(t *testing.T) {
	dht, err := New()
	if err != nil {
		t.Fatalf("Failed to create server %s.", err)
	}
	node := Node{
		addr: net.UDPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: 1234,
		},
		publicKey: dht.publicKey,
	}

	kind := netPacketPingRequest
	data, err := dht.ping(kind, node)
	if err != nil {
		t.Errorf("Failed to build getNodes. %s", err)
	}
	if len(data) != 1+32+24+1+8+box.Overhead {
		t.Errorf("Marshaled getNode is %d instead of 97, %v", len(data), data)
	}
	err = dht.handlePingPong(true, data)
	if err != nil {
		t.Errorf("Failed to parse ping. %s", err)
	}
}

func TestGetNodes(t *testing.T) {
	dht, err := New()
	if err != nil {
		t.Fatalf("Failed to create server %s.", err)
	}
	node := Node{
		addr: net.UDPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: 1234,
		},
		publicKey: publicKey,
	}

	data, err := dht.getNodes(node, publicKey)
	if err != nil {
		t.Errorf("Failed to build getNodes. %s", err)
	}
	if len(data) != 113 {
		t.Errorf("Marshaled getNode is %d instead of 97, %v", len(data), data)
	}
}

func TestMarshalNode(t *testing.T) {
	node := Node{
		addr: net.UDPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: 1234,
		},
		publicKey: publicKey,
	}
	data, err := node.MarshalBinary()
	if err != nil {
		t.Errorf("Failed to marsha node. %s", err)
	}
	if len(data) != 39 {
		t.Errorf("Marshaled node is %d instead of 39, %v", len(data), data)
	}

	node6 := Node{
		addr: net.UDPAddr{
			IP:   net.ParseIP("::1"),
			Port: 1234,
		},
		publicKey: publicKey,
	}
	data, err = node6.MarshalBinary()
	if err != nil {
		t.Errorf("Failed to marshel node. %s", err)
	}
	if len(data) != 51 {
		t.Errorf("Marshaled node is %d instead of 51, %v", len(data), data)
	}
	var node62 Node
	err = node62.UnmarshalBinary(data)
	if err != nil {
		t.Errorf("Failed to marshel node. %s", err)
	}
	// DeepEqual doesn't work on ip addresses
	//if !reflect.DeepEqual(node6, node62) {
	//	t.Errorf("Failed to unmarshal\n%v\n%v\n%v\n", node6, data, node62)
	//}
}

func TestMarshalSendNodesIPv6(t *testing.T) {
	node := Node{
		addr: net.UDPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: 1234,
		},
		publicKey: publicKey,
	}
	sendNodesIPv6 := SendNodesIPv6{
		Number:       1,
		Nodes:        []Node{node},
		SendbackData: 1,
	}
	data, err := sendNodesIPv6.MarshalBinary()
	if err != nil {
		t.Errorf("Failed to marshel node. %s", err)
	}
	if len(data) != 48 {
		t.Errorf("Marshaled node is %d instead of 48, %v", len(data), data)
	}
	var sendNodesIPv62 SendNodesIPv6
	err = sendNodesIPv62.UnmarshalBinary(data)
	if err != nil {
		t.Errorf("Failed to marshel node. %s", err)
	}
	// DeepEqual doesn't work on ip addresses
	//if !reflect.DeepEqual(sendNodesIPv6, sendNodesIPv62) {
	//	t.Errorf("Failed to unmarshal\n%v\n%v\n%v\n", sendNodesIPv6, data, sendNodesIPv62)
	//}
}

func TestBootstrap(t *testing.T) {
	dht, err := New()
	if err != nil {
		t.Fatalf("Failed to create server %s.", err)
	}
	go dht.Serve()
	defer dht.Stop()

	dht.AddFriend(publicKey)

	node := Node{
		addr: net.UDPAddr{
			IP:   net.ParseIP("::1"),
			Port: 33445,
		},
		publicKey: publicKey,
	}
	dht.Bootstrap(node)
	//ping
	data, err := dht.ping(netPacketPingRequest, node)
	if err != nil {
		t.Errorf("error %s", err)
	}
	err = dht.send(data, node)
	if err != nil {
		t.Errorf("error %s", err)
	}

	time.Sleep(time.Second)
	//<-dht.request
}
