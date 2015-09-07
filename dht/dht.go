package dht

import (
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"net"

	"golang.org/x/crypto/nacl/box"
	//"golang.org/x/crypto/nacl/secretbox"

	"github.com/vikstrous/gotox"
)

func payloadSize(packetLength int) (int, error) {
	return packetLength - gotox.PublicKeySize - gotox.NonceSize - box.Overhead - 1, nil
}

type NAT struct {
	/* 1 if currently hole punching, otherwise 0 */
	HolePunching   uint8
	PunchingIndex  uint32
	Tries          uint32
	PunchingIndex2 uint32

	PunchingTimestamp    uint64
	RecvNATpingTimestamp uint64
	NATpingID            uint64
	NATpingTimestamp     uint64
}

type IPPTsPng struct {
	Addr       net.UDPAddr // might not be udp?
	Timestamp  uint64      // What precision?
	LastPinged uint64      // timestamp?

	// hardening Hardening

	/* Returned by this node. Either our friend or us. */
	RetIPPort    net.UDPAddr // might not be udp?
	RetTimestamp uint64      // ???
}

type ClientData struct {
	PublicKey [gotox.PublicKeySize]byte
	Assoc4    IPPTsPng
	Assoc6    IPPTsPng
}

type Friend struct {
	PublicKey  [gotox.PublicKeySize]byte
	ClientList []ClientData

	/* Time at which the last get_nodes request was sent. */
	LastGetNode uint64 //??? by who?
	/* number of times get_node packets were sent. */
	BootstrapTimes uint32 //??

	/* Symetric NAT hole punching stuff. */
	Nat NAT

	lock_count uint16
	//struct {
	//    void (*ip_callback)(void *, int32_t, IP_Port);
	//    void *data;
	//    int32_t number;
	//} callbacks[DHT_FRIEND_MAX_LOCKS];

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

	// TODO: reply only to friends
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
	} else {
		// we received a pong from a friend, so we should do nat hole punching stuff
		// XXX: incomplete...

		maxUint64 := big.Int{}
		maxUint64.SetUint64(^uint64(0))
		num, err := rand.Int(rand.Reader, &maxUint64)
		if err != nil {
			return err
		}

		friend := dht.Friends[*sender]
		friend.Nat.NATpingID = pingPong.PingID
		friend.Nat.NATpingID = num.Uint64()
		friend.Nat.HolePunching = 1

	}
	return nil
}

func (dht *DHT) handleGetNodes(sender *[gotox.PublicKeySize]byte, getNodes *GetNodes, addr *net.UDPAddr) error {
	if *sender == dht.PublicKey {
		return fmt.Errorf("Rejected GetNodes from ourselves.")
	}
	data, err := dht.PackSendNodesIPv6(sender, getNodes.RequestedNodeID, getNodes.SendbackData)
	if err != nil {
		return err
	}

	err = dht.Send(data, addr)
	if err != nil {
		return err
	}

	// TODO
	//add_to_ping(dht->ping, packet + 1, source);

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
	// TODO: can we have a map of types to functions?
	switch payload := plainPacket.Payload.(type) {
	case *PingPong:
		return dht.handlePingPong(plainPacket.Sender, payload, addr)
	case *SendNodesIPv6:
		return dht.handleSendNodesIPv6(plainPacket.Sender, payload, addr)
	case *GetNodes:
		return dht.handleGetNodes(plainPacket.Sender, payload, addr)
	default:
		return fmt.Errorf("Internal error. Failed to handle payload of parsed packet.")
	}
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

func (dht *DHT) PackPacket(plainPacket *PlainPacket, publicKey *[gotox.PublicKeySize]byte) ([]byte, error) {
	encryptedPacket, err := dht.encryptPacket(plainPacket, publicKey)
	if err != nil {
		return nil, err
	}

	data, err := encryptedPacket.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return data, nil
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
	return dht.PackPacket(&plainPacket, publicKey)
}

// TODO: find the closest nodes to the requestedNodeID and return them
func (dht *DHT) PackSendNodesIPv6(recipient, requestedNodeID *[gotox.PublicKeySize]byte, sendbackData uint64) ([]byte, error) {
	if *recipient == dht.PublicKey {
		return nil, fmt.Errorf("Refusing to build SendNodesIPv6 packet to myself.")
	}

	//uint32_t num_nodes = get_close_nodes(dht, requestedNodeID, nodes_list?, 0, LAN_ip(ip_port.ip) == 0, 1);

	sendNodesIPv6 := SendNodesIPv6{
		Number:       0,
		Nodes:        []Node{},
		SendbackData: sendbackData,
	}
	plainPacket := PlainPacket{
		Sender:  &dht.PublicKey,
		Payload: &sendNodesIPv6,
	}
	return dht.PackPacket(&plainPacket, recipient)
}

// getNodes sends a getnodes request to the target
// TODO: implement sendback data? - it's used to prevent replay attacks - it can also be used to match requests with responses
// TODO: see if we can actually receive the reply here... or we should receive be async
func (dht *DHT) PackGetNodes(publicKey *[gotox.PublicKeySize]byte, queryKey [gotox.PublicKeySize]byte) ([]byte, error) {
	if *publicKey == dht.PublicKey {
		return nil, fmt.Errorf("Refusing to talk to myself.")
	}

	getNodes := GetNodes{
		RequestedNodeID: publicKey,
		SendbackData:    1,
	}
	plainPacket := PlainPacket{
		Sender:  &dht.PublicKey,
		Payload: &getNodes,
	}
	return dht.PackPacket(&plainPacket, publicKey)
}

func (dht *DHT) Bootstrap(node Node) error {
	// we add ourselves to the dht by querying ourselves???
	data, err := dht.PackGetNodes(&node.PublicKey, dht.PublicKey)
	if err != nil {
		return err
	}
	err = dht.Send(data, &node.Addr)
	if err != nil {
		return err
	}
	return nil
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
