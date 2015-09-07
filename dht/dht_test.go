package dht

import (
	"encoding/hex"
	"net"
	//"reflect"
	"testing"

	"github.com/vikstrous/gotox"
	"golang.org/x/crypto/nacl/box"
)

var qToxPublicKey = [gotox.PublicKeySize]byte{}

func init() {
	publicKeySlice, _ := hex.DecodeString("A4D28D52D4116A02147ECE6C6299DA3F5524DEBA043B067CF7D5BF2E09064032353CFD14B519")
	copy(qToxPublicKey[:], publicKeySlice)
}

func TestPing(t *testing.T) {
	dht, err := New()
	if err != nil {
		t.Fatalf("Failed to create server %s.", err)
	}
	node := Node{
		Addr: net.UDPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: 1234,
		},
		PublicKey: dht.PublicKey,
	}

	data, err := dht.PackPingPong(true, 1, &node.PublicKey)
	if err != nil {
		t.Errorf("Failed to build getNodes. %s", err)
	}
	if len(data) != 1+32+24+1+8+box.Overhead {
		t.Errorf("Marshaled getNode is %d instead of 97, %v", len(data), data)
	}
}

func TestGetNodes(t *testing.T) {
	dht, err := New()
	if err != nil {
		t.Fatalf("Failed to create server %s.", err)
	}
	node := Node{
		Addr: net.UDPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: 1234,
		},
		PublicKey: qToxPublicKey,
	}

	data, err := dht.PackGetNodes(&node.PublicKey, qToxPublicKey)
	if err != nil {
		t.Errorf("Failed to build getNodes. %s", err)
	}
	if len(data) != 113 {
		t.Errorf("Marshaled getNode is %d instead of 97, %v", len(data), data)
	}
}

func TestMarshalNode(t *testing.T) {
	node := Node{
		Addr: net.UDPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: 1234,
		},
		PublicKey: qToxPublicKey,
	}
	data, err := node.MarshalBinary()
	if err != nil {
		t.Errorf("Failed to marsha node. %s", err)
	}
	if len(data) != 39 {
		t.Errorf("Marshaled node is %d instead of 39, %v", len(data), data)
	}

	node6 := Node{
		Addr: net.UDPAddr{
			IP:   net.ParseIP("::1"),
			Port: 1234,
		},
		PublicKey: qToxPublicKey,
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
		Addr: net.UDPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: 1234,
		},
		PublicKey: qToxPublicKey,
	}
	sendNodesIPv6 := SendNodesIPv6{
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
