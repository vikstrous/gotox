package dht

import (
	"log"
	"net"
)

type LocalTransport struct {
	ChOut       *chan []byte
	ChIn        *chan []byte
	Identity    *Identity
	ReceiveFunc ReceiveFunc
}

func NewLocalTransport(id *Identity) (*LocalTransport, error) {
	chIn := make(chan []byte, 100)
	return &LocalTransport{
		ChIn:     &chIn,
		Identity: id,
	}, nil
}

func (t *LocalTransport) Send(payload Payload, dest *DHTPeer) error {
	plainPacket := PlainPacket{
		Sender:  &t.Identity.PublicKey,
		Payload: payload,
	}

	encryptedPacket, err := t.Identity.EncryptPacket(&plainPacket, &dest.PublicKey)
	if err != nil {
		return err
	}

	data, err := encryptedPacket.MarshalBinary()
	if err != nil {
		return err
	}

	*t.ChOut <- data

	return nil
}

func (t *LocalTransport) Listen() {
	for {
		data := <-*t.ChIn
		var encryptedPacket EncryptedPacket
		err := encryptedPacket.UnmarshalBinary(data)
		if err != nil {
			log.Printf("error receiving: %v", err)
			continue
		}
		plainPacket, err := t.Identity.DecryptPacket(&encryptedPacket)
		if err != nil {
			log.Printf("error receiving: %v", err)
			continue
		}
		terminate := t.ReceiveFunc(plainPacket, &net.UDPAddr{})
		if terminate {
			log.Printf("Clean termination.")
			return
		}
	}
}

func (t *LocalTransport) RegisterReceiver(receiver ReceiveFunc) {
	t.ReceiveFunc = receiver
}
