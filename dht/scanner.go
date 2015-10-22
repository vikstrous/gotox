package dht

import (
	"crypto/rand"
	"fmt"
	"math"
	"net"
	"sync"
	"time"

	"github.com/vikstrous/gotox"
)

type PeerInfo struct {
	DHTPeer
	NumRequests int
}

// Scanner implements receive
type Scanner struct {
	Transport
	// this holds all nodes discovered
	AllPeersMutex sync.Mutex
	AllPeers      map[[gotox.PublicKeySize]byte]PeerInfo
}

func NewScanner() (*Scanner, error) {
	id, err := GenerateIdentity()
	if err != nil {
		return nil, err
	}
	transport, err := NewUDPTransport(id)
	if err != nil {
		return nil, err
	}
	s := Scanner{
		Transport: transport,
		AllPeers:  make(map[[gotox.PublicKeySize]byte]PeerInfo),
	}
	transport.RegisterReceiver(&s)

	go transport.Listen()

	go s.pingerTask()

	return &s, nil
}

func (s *Scanner) pingerTask() {
	for {
		// XXX: figure out the "right" interval for this
		numPeers := len(s.AllPeers)
		fmt.Printf("peers: %d\n", numPeers)
		duration := time.Duration(uint64(math.Log(float64(numPeers)))) * 200
		s.AllPeersMutex.Lock()
		done := true
		for _, neighbour := range s.AllPeers {
			// scan only ipv4
			if neighbour.Addr.IP.To4() != nil {
				if neighbour.NumRequests < 10 {
					done = false
					err := s.Transport.Send(&GetNodes{
						RequestedNodeID: &neighbour.PublicKey,
					}, &neighbour.DHTPeer)
					if err != nil {
						fmt.Println(err)
					}
					randomPK := [gotox.PublicKeySize]byte{}
					rand.Read(randomPK[:])
					err = s.Transport.Send(&GetNodes{
						RequestedNodeID: &randomPK,
					}, &neighbour.DHTPeer)
					if err != nil {
						fmt.Println(err)
					}
					neighbour.NumRequests++
					s.AllPeers[neighbour.PublicKey] = neighbour
				}
			}
		}
		s.AllPeersMutex.Unlock()
		time.Sleep(duration * time.Millisecond)
		if numPeers == 0 {
			time.Sleep(time.Second)
		} else {
			if done {
				fmt.Println("done.")
				return
			}
		}
	}
}

func (s *Scanner) Receive(pp *PlainPacket, addr *net.UDPAddr) error {
	switch payload := pp.Payload.(type) {
	case *GetNodesReply:
		// There are only 4 replies
		s.AllPeersMutex.Lock()
		for _, node := range payload.Nodes {
			peer, found := s.AllPeers[node.PublicKey]
			// prefer ipv4
			if !found {
				s.AllPeers[node.PublicKey] = PeerInfo{DHTPeer: DHTPeer{node.PublicKey, node.Addr}}
			} else {
				if peer.Addr.IP.To4() == nil && node.Addr.IP.To4() != nil {
					s.AllPeers[node.PublicKey] = PeerInfo{DHTPeer: DHTPeer{node.PublicKey, node.Addr}}
				}
			}
		}
		s.AllPeersMutex.Unlock()
	default:
		return fmt.Errorf("Internal error. Failed to handle payload of parsed packet. %d", pp.Payload.Kind())
	}
	return nil
}
