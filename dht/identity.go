package dht

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/nacl/box"

	"github.com/vikstrous/gotox"
)

type Identity struct {
	SymmetricKey [gotox.SymmetricKeySize]byte // used for encrypting cookies?
	PublicKey    [gotox.PublicKeySize]byte
	PrivateKey   [gotox.PrivateKeySize]byte
}

func GenerateIdentity() (*Identity, error) {
	// generate identity key
	publicKey, privateKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	// generate "secret" key for dht - used for cookies?
	// XXX: this should probably be unique on every start
	symmetricKey := [gotox.SymmetricKeySize]byte{}
	_, err = rand.Read(symmetricKey[:])
	if err != nil {
		return nil, err
	}

	id := Identity{
		PublicKey:    *publicKey,
		PrivateKey:   *privateKey,
		SymmetricKey: symmetricKey,
	}
	return &id, nil
}

// TODO: make EncryptPacket, Encrypt, DecryptPacket methods on an Identity
func EncryptPacket(plain *PlainPacket, publicKey *[gotox.PublicKeySize]byte, privateKey *[gotox.PrivateKeySize]byte) (*EncryptedPacket, error) {
	encrypted := EncryptedPacket{
		Kind:   plain.Payload.Kind(),
		Sender: plain.Sender,
	}
	// binary encode the data
	payload, err := plain.Payload.MarshalBinary()
	if err != nil {
		return nil, err
	}
	// encrypt payload into encrypted.Payload
	nonce, cyphertext, err := Encrypt(payload, publicKey, privateKey)
	if err != nil {
		return nil, err
	}
	encrypted.Nonce = nonce
	encrypted.Payload = cyphertext
	return &encrypted, nil
}

// TODO: cache the shared key
func Encrypt(plain []byte, publicKey *[gotox.PublicKeySize]byte, privateKey *[gotox.PrivateKeySize]byte) (*[gotox.NonceSize]byte, []byte, error) {
	nonce := [gotox.NonceSize]byte{}
	// generate and write nonce
	_, err := rand.Read(nonce[:])
	if err != nil {
		return nil, nil, err
	}
	encrypted := box.Seal(nil, plain, &nonce, publicKey, privateKey)
	return &nonce, encrypted, nil
}

func DecryptPacket(encrypted *EncryptedPacket, privateKey *[gotox.PrivateKeySize]byte) (*PlainPacket, error) {
	plain := PlainPacket{
		Sender: encrypted.Sender,
	}
	switch encrypted.Kind {
	case netPacketPing:
		plain.Payload = &PingPong{}
	case netPacketPong:
		plain.Payload = &PingPong{}
	case netPacketGetNodes:
		plain.Payload = &GetNodes{}
	case netPacketGetNodesReply:
		plain.Payload = &GetNodesReply{}
	default:
		return nil, fmt.Errorf("Unknown packet type %d.", encrypted.Kind)
	}

	plainPayload, success := box.Open(nil, encrypted.Payload, encrypted.Nonce, encrypted.Sender, privateKey)
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
