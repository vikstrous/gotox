package dht

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"net"

	"golang.org/x/crypto/nacl/box"
	//"golang.org/x/crypto/nacl/secretbox"

	"github.com/vikstrous/gotox"
)

var DhtServerList []Node

func init() {
	// TODO: read these from a config file
	// "sonOfRa",
	key32 := [32]byte{}
	key, _ := hex.DecodeString("04119E835DF3E78BACF0F84235B300546AF8B936F035185E2A8E9E0A67C8924F")
	copy(key32[:], key)
	DhtServerList = []Node{
		Node{
			PublicKey: key32,
			Addr: net.UDPAddr{
				IP:   []byte{144, 76, 60, 215},
				Port: 33445,
			},
		},
	}
}

//name=stal
//userId=A09162D68618E742FFBCA1C2C70385E6679604B2D80EA6E84AD0996A1AC8A074
//address=23.226.230.47
//port=33445
//name=Munrek
//userId=E398A69646B8CEACA9F0B84F553726C1C49270558C57DF5F3C368F05A7D71354
//address=195.154.119.113
//port=33445
//name=nurupo
//userId=F404ABAA1C99A9D37D61AB54898F56793E1DEF8BD46B1038B9D822E8460FAB67
//address=192.210.149.121
//port=33445
//name=Impyy
//userId=788236D34978D1D5BD822F0A5BEBD2C53C64CC31CD3149350EE27D4D9A2F9B6B
//address=178.62.250.138
//port=33445
//name=Manolis
//userId=461FA3776EF0FA655F1A05477DF1B3B614F7D6B124F7DB1DD4FE3C08B03B640F
//address=130.133.110.14
//port=33445
//name=noisykeyboard
//userId=5918AC3C06955962A75AD7DF4F80A5D7C34F7DB9E1498D2E0495DE35B3FE8A57
//address=104.167.101.29
//port=33445
//name=Busindre
//userId=A179B09749AC826FF01F37A9613F6B57118AE014D4196A0E1105A98F93A54702
//address=205.185.116.116
//port=33445
//name=Busindre
//userId=1D5A5F2F5D6233058BF0259B09622FB40B482E4FA0931EB8FD3AB8E7BF7DAF6F
//address=198.98.51.198
//port=33445
//name=ray65536
//userId=8E7D0B859922EF569298B4D261A8CCB5FEA14FB91ED412A7603A585A25698832
//address=108.61.165.198
//port=33445
//name=Kr9r0x
//userId=C4CEB8C7AC607C6B374E2E782B3C00EA3A63B80D4910B8649CCACDD19F260819
//address=212.71.252.109
//port=33445
//name=fluke571
//userId=3CEE1F054081E7A011234883BC4FC39F661A55B73637A5AC293DDF1251D9432B
//address=194.249.212.109
//port=33445
//name=MAH69K
//userId=DA4E4ED4B697F2E9B000EEFE3A34B554ACD3F45F5C96EAEA2516DD7FF9AF7B43
//address=185.25.116.107
//port=33445
//name=WIeschie
//userId=6A4D0607A296838434A6A7DDF99F50EF9D60A2C510BBF31FE538A25CB6B4652F
//address=192.99.168.140
//port=33445

//TODO: store the ip type because it might be tcp
type Node struct {
	PublicKey [gotox.PublicKeySize]byte
	// TODO: don't assume a node has only one address?
	Addr net.UDPAddr
}

// TODO: rename SendbackData to RequestID
type GetNodes struct {
	RequestedNodeID *[gotox.PublicKeySize]byte
	SendbackData    uint64
}

type SendNodesIPv6 struct {
	Nodes        []Node
	SendbackData uint64
}

type EncryptedPacket struct {
	Kind    uint8
	Sender  *[gotox.PublicKeySize]byte
	Nonce   *[gotox.NonceSize]byte
	Payload []byte
}

type BinaryMarshalable interface {
	MarshalBinary() (data []byte, err error)
	UnmarshalBinary(data []byte) error
}

type PlainPacket struct {
	Sender  *[gotox.PublicKeySize]byte
	Payload BinaryMarshalable
}

// TODO: rename PingID to RequestID
type PingPong struct {
	IsPing bool
	PingID uint64
}

// packedNodeSizeIp6
// 1 + 32 + 24 + 1 + n*(32+1+16+2) + 8 + overhead
//
// [byte with value: 04]
// [char array  (client node_id), length=32 bytes]
// [random 24 byte nonce]
// [Encrypted with the nonce and private key of the sender:
//     [uint8_t number of nodes in this packet]
//     [Nodes in node format, length=?? * (number of nodes (maximum of 4 nodes)) bytes]
//     [Sendback data, length=8 bytes]
// ]

//[char array (node_id), length=32 bytes]
//[uint8_t family (2 == IPv4, 10 == IPv6, 130 == TCP IPv4, 138 == TCP IPv6)]
//[ip (in network byte order), length=4 bytes if ipv4, 16 bytes if ipv6]
//[port (in network byte order), length=2 bytes]

func (sn *SendNodesIPv6) MarshalBinary() ([]byte, error) {
	buf := new(bytes.Buffer)
	if len(sn.Nodes) > 4 {
		return nil, fmt.Errorf("Attempt to send too many nodes in reply: %d", len(sn.Nodes))
	}

	// number
	err := binary.Write(buf, binary.LittleEndian, uint8(len(sn.Nodes)))
	if err != nil {
		return nil, err
	}

	// nodes
	for _, node := range sn.Nodes {
		nodeBytes, err := node.MarshalBinary()
		if err != nil {
			return nil, err
		}

		_, err = buf.Write(nodeBytes)
		if err != nil {
			return nil, err
		}
	}

	// sendback data
	err = binary.Write(buf, binary.LittleEndian, sn.SendbackData)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), err
}

func (sn *SendNodesIPv6) UnmarshalBinary(data []byte) error {
	// TODO: check length

	log.Printf("sendNodesIPv6 data %v %d", data, len(data))
	// number of nodes
	numNodes := uint8(len(sn.Nodes))
	binary.Read(bytes.NewReader(data), binary.LittleEndian, &numNodes)

	// nodes
	sn.Nodes = make([]Node, numNodes)
	offset := 1
	for n := uint8(0); n < numNodes; n++ {
		var nodeSize int
		if data[offset] == AF_INET || data[offset] == TCP_INET {
			nodeSize = packedNodeSizeIPv4
		} else if data[offset] == AF_INET6 || data[offset] == TCP_INET6 {
			nodeSize = packedNodeSizeIPv6
		} else {
			return fmt.Errorf("Unknown ip type %d", data[offset])
		}
		err := sn.Nodes[n].UnmarshalBinary(data[offset : offset+nodeSize])
		if err != nil {
			return err
		}
		offset += nodeSize
	}

	// sendback data
	return binary.Read(bytes.NewReader(data[offset:]), binary.LittleEndian, &sn.SendbackData)
}

func (n *Node) MarshalBinary() ([]byte, error) {
	// TODO: support TCP
	buf := new(bytes.Buffer)
	var err error
	if ipv4 := n.Addr.IP.To4(); ipv4 != nil {
		// family 1 byte
		err = binary.Write(buf, binary.LittleEndian, AF_INET)
		if err != nil {
			return nil, err
		}
		// address 4 bytes
		_, err = buf.Write(ipv4)
		if err != nil {
			return nil, err
		}
	} else if ipv6 := n.Addr.IP.To16(); ipv6 != nil {
		// family 1 byte
		err = binary.Write(buf, binary.LittleEndian, AF_INET6)
		if err != nil {
			return nil, err
		}
		// address 16 bytes
		_, err = buf.Write(ipv6)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("Invalid node address for node %v", n)
	}
	// port 2 bytes
	err = binary.Write(buf, binary.LittleEndian, uint16(n.Addr.Port))
	if err != nil {
		return nil, err
	}
	// public key 32 bytes
	_, err = buf.Write(n.PublicKey[:])
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (n *Node) UnmarshalBinary(data []byte) error {
	if len(data) != packedNodeSizeIPv4 && len(data) != packedNodeSizeIPv6 {
		return fmt.Errorf("Wrong size data for node %d", len(data))
	}

	log.Printf("parsing %v %d", data, len(data))
	// ip type
	ipType := data[0]

	var ipSize int
	// confirm ip type
	if ipType == AF_INET || ipType == TCP_INET {
		ipSize = 4
	} else if ipType == AF_INET6 || ipType == TCP_INET6 {
		ipSize = 16
	} else {
		return fmt.Errorf("Unknown ip type %d", ipType)
	}
	n.Addr.IP = data[1 : 1+ipSize]

	// port
	var port uint16
	err := binary.Read(bytes.NewReader(data[1+ipSize:]), binary.LittleEndian, &port)
	if err != nil {
		return err
	}
	n.Addr.Port = int(port)

	// public key
	copy(n.PublicKey[:], data[1+ipSize+2:])
	return nil
}

func (p *EncryptedPacket) UnmarshalBinary(data []byte) error {
	if len(data) < 1+gotox.PublicKeySize+gotox.NonceSize {
		return fmt.Errorf("Packet too small to be valid %d", len(data))
	}
	p.Kind = uint8(data[0])
	p.Sender = new([gotox.PublicKeySize]byte)
	copy(p.Sender[:], data[1:1+gotox.PublicKeySize])
	p.Nonce = new([gotox.NonceSize]byte)
	copy(p.Nonce[:], data[1+gotox.PublicKeySize:1+gotox.PublicKeySize+gotox.NonceSize])
	p.Payload = data[1+gotox.PublicKeySize+gotox.NonceSize:]
	return nil
}

func (p *EncryptedPacket) MarshalBinary() ([]byte, error) {
	buf := new(bytes.Buffer)

	// 1 byte message type
	err := binary.Write(buf, binary.LittleEndian, p.Kind)
	if err != nil {
		return nil, err
	}

	// 32 byte public key
	_, err = buf.Write(p.Sender[:])
	if err != nil {
		return nil, err
	}

	// write the nonce
	_, err = buf.Write(p.Nonce[:])
	if err != nil {
		return nil, err
	}

	// write the encrypted message
	_, err = buf.Write(p.Payload)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// TODO: cache the shared key
// TODO: use sequential nonces to avoid using too much randomness
func (dht *DHT) encryptPacket(plain *PlainPacket, publicKey *[gotox.PublicKeySize]byte) (*EncryptedPacket, error) {
	var kind uint8
	switch pl := plain.Payload.(type) {
	case *PingPong:
		if pl.IsPing {
			kind = netPacketPingRequest
		} else {
			kind = netPacketPingResponse
		}
	case *GetNodes:
		kind = netPacketGetNodes
	case *SendNodesIPv6:
		kind = netPacketSendNodesIPv6
	default:
		return nil, fmt.Errorf("Internal error. Unknown payload type.")
	}
	encrypted := EncryptedPacket{
		Kind:   kind,
		Sender: plain.Sender,
	}
	// binary encode the data
	payload, err := plain.Payload.MarshalBinary()
	if err != nil {
		return nil, err
	}
	// encrypt payload into encrypted.Payload
	nonce, cyphertext, err := dht.encrypt(payload, publicKey)
	if err != nil {
		return nil, err
	}
	encrypted.Nonce = nonce
	encrypted.Payload = cyphertext
	return &encrypted, nil
}

func (dht *DHT) decryptPacket(encrypted *EncryptedPacket) (*PlainPacket, error) {
	plain := PlainPacket{
		Sender: encrypted.Sender,
	}
	switch encrypted.Kind {
	case netPacketPingRequest:
		plain.Payload = &PingPong{}
	case netPacketPingResponse:
		plain.Payload = &PingPong{}
	case netPacketGetNodes:
		plain.Payload = &GetNodes{}
	case netPacketSendNodesIPv6:
		plain.Payload = &SendNodesIPv6{}
	default:
		return nil, fmt.Errorf("Unknown packet type %d.", encrypted.Kind)
	}

	plainPayload, success := box.Open(nil, encrypted.Payload, encrypted.Nonce, encrypted.Sender, &dht.PrivateKey)
	if !success {
		return nil, fmt.Errorf("Failed to decrypt.")
	}

	// decrypt payload
	err := plain.Payload.UnmarshalBinary(plainPayload)
	if err != nil {
		return nil, err
	}

	return &plain, nil
}

func (p *PingPong) MarshalBinary() ([]byte, error) {
	data := new(bytes.Buffer)
	var kind uint8
	if p.IsPing {
		kind = netPacketPingRequest
	} else {
		kind = netPacketPingResponse
	}
	// request or respense
	err := binary.Write(data, binary.LittleEndian, kind)
	if err != nil {
		return nil, err
	}
	// pind id
	err = binary.Write(data, binary.LittleEndian, p.PingID)
	if err != nil {
		return nil, err
	}
	// finalize message to be encrypted
	return data.Bytes(), nil
}

func (p *PingPong) UnmarshalBinary(data []byte) error {
	if len(data) < 1+8 {
		return fmt.Errorf("Wrong size data for ping %d.", len(data))
	}
	if data[0] == netPacketPingRequest {
		p.IsPing = true
	} else if data[0] == netPacketPingResponse {
		p.IsPing = false
	} else {
		return fmt.Errorf("Unknown ping type %d.", data[0])
	}
	return binary.Read(bytes.NewReader(data[1:]), binary.LittleEndian, &p.PingID)
}

func (sn *GetNodes) MarshalBinary() ([]byte, error) {
	buf := new(bytes.Buffer)
	// node id
	_, err := buf.Write(sn.RequestedNodeID[:])
	if err != nil {
		return nil, err
	}
	// sendback data
	err = binary.Write(buf, binary.LittleEndian, sn.SendbackData)
	if err != nil {
		return nil, err
	}
	// finalize message to be encrypted
	return buf.Bytes(), nil
}

func (sn *GetNodes) UnmarshalBinary(data []byte) error {
	//TODO: check length
	sn.RequestedNodeID = new([gotox.PublicKeySize]byte)
	copy(sn.RequestedNodeID[:], data[:gotox.PublicKeySize])
	return binary.Read(bytes.NewReader(data[gotox.PublicKeySize:gotox.PublicKeySize+gotox.SendbackDataSize]), binary.LittleEndian, &sn.SendbackData)
}
