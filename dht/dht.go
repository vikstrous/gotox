package dht

import (
	"crypto/rand"
	"fmt"
	"log"
	"net"

	"golang.org/x/crypto/nacl/box"
	//"golang.org/x/crypto/nacl/secretbox"

	"github.com/vikstrous/gotox"
)

func payloadSize(packetLength int) (int, error) {
	return packetLength - gotox.PublicKeySize - gotox.NonceSize - box.Overhead - 1, nil
}

type Friend struct {
	publicKey [gotox.PublicKeySize]byte
}

type DHT struct {
	server       net.UDPConn
	request      chan bool
	symmetricKey [gotox.SymmetricKeySize]byte
	publicKey    [gotox.PublicKeySize]byte
	privateKey   [gotox.PrivateKeySize]byte
	addrToFriend map[net.Addr][gotox.PublicKeySize]byte
	friends      map[[gotox.PublicKeySize]byte]Friend
}

func New() (*DHT, error) {
	listener, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}

	// generate identity key
	publicKey, privateKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	// generate "secret" key for dht
	symmetricKey := [gotox.SymmetricKeySize]byte{}
	_, err = rand.Read(symmetricKey[:])
	if err != nil {
		return nil, err
	}

	dht := DHT{
		server:       *listener,
		request:      make(chan bool),
		symmetricKey: symmetricKey,
		publicKey:    *publicKey,
		privateKey:   *privateKey,
	}

	dht.addrToFriend = make(map[net.Addr][gotox.PublicKeySize]byte)
	dht.friends = make(map[[gotox.PublicKeySize]byte]Friend)

	// TODO: set up pinger

	// TODO: add fakeFriendNumber friends

	return &dht, nil
}

// handlePong assumes the message is the right size
func (dht *DHT) handlePingPong(ping bool, data []byte) error {
	var encryptedPacket EncryptedPacket
	err := encryptedPacket.UnmarshalBinary(data)
	if err != nil {
		return err
	}
	plainPacket, err := dht.decryptPacket(&encryptedPacket)
	if err != nil {
		return err
	}
	switch plainPacket.Payload.(type) {
	case *PingPong:
	default:
		return fmt.Errorf("Internal error. Failed to parse PingPong")
	}
	pingPong := plainPacket.Payload.(*PingPong)
	if pingPong.IsPing != ping {
		return fmt.Errorf("Not a ping. Spoofed packet?")
	}
	log.Printf("Received pingpong: %b %d", ping, pingPong.PingID)
	return nil
}

func (dht *DHT) handleSendNodesIPv6(data []byte) error {
	var encryptedPacket EncryptedPacket
	err := encryptedPacket.UnmarshalBinary(data)
	if err != nil {
		return err
	}
	plainPacket, err := dht.decryptPacket(&encryptedPacket)
	if err != nil {
		return err
	}
	switch plainPacket.Payload.(type) {
	case *SendNodesIPv6:
	default:
		return fmt.Errorf("Internal error. Failed to parse SendNodesIPv6")
	}
	sn := plainPacket.Payload.(*SendNodesIPv6)
	log.Printf("Received SendNodesIPv6: %v", sn)
	return nil
}

func (dht *DHT) send(data []byte, node Node) error {
	_, _, err := dht.server.WriteMsgUDP(data, nil, &node.addr)
	return err
}

func (dht *DHT) Serve() {
	for {
		buffer := make([]byte, 2048)
		// TODO: can we make this buffer smaller?
		oob := make([]byte, 2048)
		// n, oobn, flags, addr, err
		buffer_length, _, _, _, err := dht.server.ReadMsgUDP(buffer, oob)
		if err != nil {
			// This is usually how we stop the server
			// Do any necessary cleanup here.
			//log.Fatal(err)
			close(dht.request)
			return
		}

		if buffer_length >= 1 {
			message := buffer[:buffer_length]
			log.Printf("Message type %d\n", buffer[0])
			switch buffer[0] {
			case netPacketPingResponse:
				err = dht.handlePingPong(false, message)
			case netPacketPingRequest:
				err = dht.handlePingPong(true, message)
			case netPacketSendNodesIPv6:
				err = dht.handleSendNodesIPv6(message)
			default:
				log.Printf("Unhandled message received: %d", message[0])
				close(dht.request)
				return
			}
			if err != nil {
				log.Printf("Error handling message received: %v", err)
				err = nil
			}
		} else {
			log.Printf("Received empty message")
			close(dht.request)
			return
		}
		//TODO: look up peer in friends list
		//dht.handle(buffer)

		//select {
		//case <-s.request:
		//}
	}
}

// TODO: cache the shared key
// TODO: use sequential nonces to avoid using too much randomness
func (dht *DHT) encrypt(plain []byte, publicKey *[gotox.PublicKeySize]byte) (*[gotox.NonceSize]byte, []byte, error) {
	nonce := [gotox.NonceSize]byte{}
	// generate and write nonce
	_, err := rand.Read(nonce[:])
	if err != nil {
		return nil, nil, err
	}
	encrypted := box.Seal(nil, plain, &nonce, publicKey, &dht.privateKey)
	return &nonce, encrypted, nil
}

func (dht *DHT) ping(kind uint8, node Node) ([]byte, error) {
	pingPong := PingPong{
		IsPing: true,
		PingID: 1,
	}
	plainPacket := PlainPacket{
		Sender:  &dht.publicKey,
		Payload: &pingPong,
	}

	encryptedPacket, err := dht.encryptPacket(&plainPacket, node.publicKey)
	if err != nil {
		return nil, err
	}

	data, err := encryptedPacket.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return data, nil
}

// getNodes sends a getnodes request to the target
// TODO: implement sendback data?
// TODO: see if we can actually receive the reply here... or we should receive be async
func (dht *DHT) getNodes(node Node, queryKey [gotox.PublicKeySize]byte) ([]byte, error) {
	if node.publicKey == dht.publicKey {
		return nil, fmt.Errorf("Refusing to talk to myself.")
	}

	getNodes := GetNodes{
		RequestedNodeID: new([gotox.PublicKeySize]byte),
		SendbackData:    1,
	}
	copy(getNodes.RequestedNodeID[:], dht.publicKey[:])
	plainPacket := PlainPacket{
		Sender:  &dht.publicKey,
		Payload: &getNodes,
	}

	encryptedPacket, err := dht.encryptPacket(&plainPacket, node.publicKey)
	if err != nil {
		return nil, err
	}

	data, err := encryptedPacket.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (dht *DHT) Bootstrap(node Node) {
	// we add ourselves to the dht by querying ourselves
	dht.getNodes(node, dht.publicKey)
}

// TODO: make it possible to communicate with this friend - maybe give the caller a channel? maybe return a Friend
// maybe associate some data with the friend?
// This adds a one more user to a friend in the dht; first it looks up the friend by the public key, then it increments the number of users of the friend
func (dht *DHT) AddFriend(publicKey [gotox.PublicKeySize]byte) error {
	dht.friends[publicKey] = Friend{
		publicKey: publicKey,
	}
	return nil
}

func (dht *DHT) Stop() {
	dht.server.Close()
}
