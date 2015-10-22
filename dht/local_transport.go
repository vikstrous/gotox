package dht

import (
	"log"
	"net"
)

type LocalTransport struct {
	ChOut    *chan []byte
	ChIn     *chan []byte
	Identity *Identity
	Receiver Receiver
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

	encryptedPacket, err := EncryptPacket(&plainPacket, &dest.PublicKey, &t.Identity.PrivateKey)
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
		plainPacket, err := DecryptPacket(&encryptedPacket, &t.Identity.PrivateKey)
		if err != nil {
			log.Printf("error receiving: %v", err)
			continue
		}
		t.Receiver.Receive(plainPacket, &net.UDPAddr{})
		if err != nil {
			log.Printf("Error handling message received: %v", err)
			continue
		}
	}
}

func (t *LocalTransport) RegisterReceiver(receiver Receiver) {
	t.Receiver = receiver
}
