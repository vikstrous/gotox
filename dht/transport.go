package dht

import (
	"log"
	"net"
)

//  Transport/Listen[with identity] -> Application/Receiver.Receive() ...
//  Transport/Sender[with identity].Send()
//  Application whatever -> Transport/Sender[with identity].Send()

// return true to terminate the listener
type ReceiveFunc func(*PlainPacket, *net.UDPAddr) bool

type Transport interface {
	Send(payload Payload, dest *DHTPeer) error
	Listen()
	RegisterReceiver(receiver ReceiveFunc)
}

type UDPTransport struct {
	Server      net.UDPConn
	Identity    *Identity
	ReceiveFunc ReceiveFunc
}

func NewUDPTransport(id *Identity) (*UDPTransport, error) {
	listener, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}

	return &UDPTransport{
		Server:   *listener,
		Identity: id,
	}, nil
}

func (t *UDPTransport) Send(payload Payload, dest *DHTPeer) error {
	plainPacket := PlainPacket{
		Sender:  &t.Identity.PublicKey,
		Payload: payload,
	}

	encryptedPacket, err := EncryptPacket(&plainPacket, &dest.PublicKey, &t.Identity.PrivateKey)
	if err != nil {
		return err
	}

	data, err := encryptedPacket.MarshalBinary()
	if err != nil {
		return err
	}

	_, _, err = t.Server.WriteMsgUDP(data, nil, &dest.Addr)
	return err
}

func (t *UDPTransport) Listen() {
	for {
		buffer := make([]byte, 2048)
		// TODO: can we make this buffer smaller?
		oob := make([]byte, 2048)
		// n, oobn, flags, addr, err
		buffer_length, _, _, addr, err := t.Server.ReadMsgUDP(buffer, oob)
		if err != nil {
			// This is usually how we stop the server
			// Do any necessary cleanup here.
			//log.Fatal(err)
			log.Printf("fatal error receiving: %v", err)
			return
		}

		if buffer_length >= 1 {
			var encryptedPacket EncryptedPacket
			err := encryptedPacket.UnmarshalBinary(buffer[:buffer_length])
			if err != nil {
				log.Printf("error receiving: %v", err)
				continue
			}
			plainPacket, err := DecryptPacket(&encryptedPacket, &t.Identity.PrivateKey)
			if err != nil {
				log.Printf("error receiving: %v", err)
				continue
			}
			terminate := t.ReceiveFunc(plainPacket, addr)
			if terminate {
				log.Printf("Clean termination.")
				return
			}
		} else {
			log.Printf("Received empty message???")
			continue
		}
	}
}

func (t *UDPTransport) RegisterReceiver(receiver ReceiveFunc) {
	t.ReceiveFunc = receiver
}
