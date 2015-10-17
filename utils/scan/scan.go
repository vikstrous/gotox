package main

import (
	"fmt"
	//"net"

	//"github.com/vikstrous/gotox"
	"github.com/vikstrous/gotox/dht"
)

func main() {
	dhtServer, err := dht.New()
	if err != nil {
		fmt.Printf("Failed to create server %s.\n", err)
		return
	}
	go dhtServer.Serve()
	defer dhtServer.Stop()

	//for _, server := range dht.DhtServerList[:5] {
	//	data, err := dhtServer.PackPingPong(true, 1, &server.PublicKey)
	//	if err != nil {
	//		fmt.Printf("error %s\n", err)
	//		return
	//	}
	//	err = dhtServer.Send(data, &server.Addr)
	//	if err != nil {
	//		fmt.Printf("error %s\n", err)
	//		return
	//	}
	//}

	//pk := [gotox.PublicKeySize]byte{216, 15, 194, 180, 236, 160, 49, 215, 12, 178, 146, 161, 223, 122, 46, 103, 236, 235, 197, 62, 25, 155, 84, 92, 195, 80, 77, 202, 42, 255, 24, 110}
	//addr := net.UDPAddr{net.IP{37, 59, 63, 23}, 42370, ""}

	//data, err := dhtServer.PackGetNodes(&pk, &pk)
	//if err != nil {
	//	fmt.Printf("error %s\n", err)
	//	return
	//}
	//err = dhtServer.Send(data, &addr)
	//if err != nil {
	//	fmt.Printf("error %s\n", err)
	//	return
	//}

	for _, server := range dht.DhtServerList[:5] {
		data, err := dhtServer.PackGetNodes(&server.PublicKey, &server.PublicKey)
		if err != nil {
			fmt.Printf("error %s\n", err)
			return
		}
		err = dhtServer.Send(data, &server.Addr)
		if err != nil {
			fmt.Printf("error %s\n", err)
			return
		}
	}

	<-dhtServer.Request
}
