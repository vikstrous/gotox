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
	PublicKey [gotox.PublicKeySize]byte
}

type DHT struct {
	Server       net.UDPConn
	Request      chan bool
	SymmetricKey [gotox.SymmetricKeySize]byte
	PublicKey    [gotox.PublicKeySize]byte
	PrivateKey   [gotox.PrivateKeySize]byte
	AddrToFriend map[net.Addr][gotox.PublicKeySize]byte
	Friends      map[[gotox.PublicKeySize]byte]Friend
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
		Server:       *listener,
		Request:      make(chan bool),
		SymmetricKey: symmetricKey,
		PublicKey:    *publicKey,
		PrivateKey:   *privateKey,
	}

	dht.AddrToFriend = make(map[net.Addr][gotox.PublicKeySize]byte)
	dht.Friends = make(map[[gotox.PublicKeySize]byte]Friend)

	// TODO: set up pinger

	// TODO: add fakeFriendNumber friends

	return &dht, nil
}

// handlePong assumes the message is the right size
func (dht *DHT) handlePingPong(sender *[gotox.PublicKeySize]byte, pingPong *PingPong, addr *net.UDPAddr) error {
	// We don't care if the ping bit inside the encrypted message matches the outside. We just handle pings and pongs the same way
	// at the outside.
	log.Printf("Received pingpong: %v", pingPong)

	if pingPong.IsPing {
		// send a pong back!
		data, err := dht.PackPingPong(false, pingPong.PingID, sender)
		if err != nil {
			return err
		}
		err = dht.Send(data, addr)
		if err != nil {
			return err
		}
	}
	return nil
}

func (dht *DHT) handleSendNodesIPv6(sender *[gotox.PublicKeySize]byte, sn *SendNodesIPv6, addr *net.UDPAddr) error {
	log.Printf("Received SendNodesIPv6: %v", sn)
	return nil
}

func (dht *DHT) handlePacket(data []byte, addr *net.UDPAddr) error {
	var encryptedPacket EncryptedPacket
	err := encryptedPacket.UnmarshalBinary(data)
	if err != nil {
		return err
	}
	plainPacket, err := dht.decryptPacket(&encryptedPacket)
	if err != nil {
		return err
	}
	switch payload := plainPacket.Payload.(type) {
	case *PingPong:
		dht.handlePingPong(plainPacket.Sender, payload, addr)
	case *SendNodesIPv6:
		dht.handleSendNodesIPv6(plainPacket.Sender, payload, addr)
	default:
		return fmt.Errorf("Internal error. Failed to handle payload of parsed packet.")
	}
	return nil
}

func (dht *DHT) Send(data []byte, addr *net.UDPAddr) error {
	fmt.Printf("sending %v\n", data)
	_, _, err := dht.Server.WriteMsgUDP(data, nil, addr)
	return err
}

func (dht *DHT) Serve() {
	for {
		buffer := make([]byte, 2048)
		// TODO: can we make this buffer smaller?
		oob := make([]byte, 2048)
		// n, oobn, flags, addr, err
		buffer_length, _, _, addr, err := dht.Server.ReadMsgUDP(buffer, oob)
		if err != nil {
			// This is usually how we stop the server
			// Do any necessary cleanup here.
			//log.Fatal(err)
			close(dht.Request)
			return
		}

		if buffer_length >= 1 {
			message := buffer[:buffer_length]
			dht.handlePacket(message, addr)
			if err != nil {
				log.Printf("Error handling message received: %v", err)
				err = nil
			}
		} else {
			log.Printf("Received empty message")
			close(dht.Request)
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
	encrypted := box.Seal(nil, plain, &nonce, publicKey, &dht.PrivateKey)
	return &nonce, encrypted, nil
}

func (dht *DHT) PackPingPong(isPing bool, pingID uint64, publicKey *[gotox.PublicKeySize]byte) ([]byte, error) {
	pingPong := PingPong{
		IsPing: isPing,
		PingID: pingID,
	}
	plainPacket := PlainPacket{
		Sender:  &dht.PublicKey,
		Payload: &pingPong,
	}

	encryptedPacket, err := dht.encryptPacket(&plainPacket, publicKey)
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
// TODO: implement sendback data? - it's used to prevent replay attacks - it can also be used to match requests with responses
// TODO: see if we can actually receive the reply here... or we should receive be async
func (dht *DHT) PackGetNodes(node Node, queryKey [gotox.PublicKeySize]byte) ([]byte, error) {
	if node.PublicKey == dht.PublicKey {
		return nil, fmt.Errorf("Refusing to talk to myself.")
	}

	getNodes := GetNodes{
		RequestedNodeID: new([gotox.PublicKeySize]byte),
		SendbackData:    1,
	}
	copy(getNodes.RequestedNodeID[:], dht.PublicKey[:])
	plainPacket := PlainPacket{
		Sender:  &dht.PublicKey,
		Payload: &getNodes,
	}

	encryptedPacket, err := dht.encryptPacket(&plainPacket, &node.PublicKey)
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
	// we add ourselves to the dht by querying ourselves???
	dht.PackGetNodes(node, dht.PublicKey)
}

// TODO: make it possible to communicate with this friend - maybe give the caller a channel? maybe return a Friend
// maybe associate some data with the friend?
// This adds a one more user to a friend in the dht; first it looks up the friend by the public key, then it increments the number of users of the friend
func (dht *DHT) AddFriend(publicKey [gotox.PublicKeySize]byte) error {
	dht.Friends[publicKey] = Friend{
		PublicKey: publicKey,
	}
	return nil
}

func (dht *DHT) Stop() {
	dht.Server.Close()
}
