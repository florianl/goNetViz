package main

import (
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"os"
)

func handlePackets(ps *gopacket.PacketSource) {
	for packet := range ps.Packets() {
		fmt.Println(packet.Metadata().CaptureInfo.Timestamp.UTC())
		fmt.Println(packet.Data())
	}
}

func availableInterfaces() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}

	for _, device := range devices {
		if len(device.Addresses) == 0 {
			continue
		}
		fmt.Println("Interface: ", device.Name)
		for _, address := range device.Addresses {
			fmt.Println("   IP address:  ", address.IP)
			fmt.Println("   Subnet mask: ", address.Netmask)
		}
		fmt.Println("")
	}
}

func main() {
	var err error
	var handle *pcap.Handle

	dev := flag.String("interface", "lo", "Chose an interface")
	filter := flag.String("filter", "", "Set a specific filter")
	lst := flag.Bool("list_interfaces", false, "List available interfaces")
	flag.Parse()

	if *lst {
		availableInterfaces()
		return
	}

	handle, err = pcap.OpenLive(*dev, 4096, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
	defer handle.Close()

	if len(*filter) != 0 {
		err = handle.SetBPFFilter(*filter)
		if err != nil {
			log.Fatal(err, "\tInvalid filter: ", *filter)
			os.Exit(1)
		}
	}

	packetSource := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	packetSource.DecodeOptions = gopacket.Lazy

	handlePackets(packetSource)

}
