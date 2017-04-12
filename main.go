package main

import (
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"image"
	"image/color"
	"image/png"
	"log"
	"os"
)

const Version = "0.0.1"

func handlePackets(ps *gopacket.PacketSource, img *image.NRGBA, num uint) {
	var count uint
	var y int
	for packet := range ps.Packets() {
		var i int
		var j int
		count++
		if count > num {
			break
		}
		elements := packet.Data()
		for i = 0; i+3 <= len(elements); i += 3 {
			img.Set(j, y, color.NRGBA{
				R: uint8(elements[i] & 255),
				G: uint8(elements[i+1] & 255),
				B: uint8(elements[i+2] & 255),
				A: 255})
			j++
		}
		switch len(elements) - i {
		case 2:
			img.Set(j, y, color.NRGBA{
				R: uint8(elements[i] & 255),
				G: uint8(elements[i+1] & 255),
				B: uint8(0),
				A: 255})
			break
		case 1:
			img.Set(j, y, color.NRGBA{
				R: uint8(elements[i] & 255),
				G: uint8(0 & 255),
				B: uint8(0 & 255),
				A: 255})
			break
		default:
		}
		y++
	}
	return
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

	dev := flag.String("interface", "", "Choose an interface for online processing")
	file := flag.String("file", "", "Choose a file for offline processing")
	filter := flag.String("filter", "", "Set a specific filter")
	lst := flag.Bool("list_interfaces", false, "List available interfaces")
	vers := flag.Bool("version", false, "Show version")
	help := flag.Bool("help", false, "Show help")
	num := flag.Uint("count", 10, "Number of packets to process")
	output := flag.String("output", "image.png", "Name of the resulting image")
	flag.Parse()

	if *lst {
		availableInterfaces()
		return
	}

	if *vers {
		fmt.Println("Version:", Version)
		return
	}

	if *help {
		flag.PrintDefaults()
		return
	}

	if len(*dev) > 0 {
		handle, err = pcap.OpenLive(*dev, 4096, true, pcap.BlockForever)
		if err != nil {
			log.Fatal(err)
			os.Exit(1)
		}
	} else if len(*file) > 0 {
		handle, err = pcap.OpenOffline(*file)
		if err != nil {
			log.Fatal(err)
			os.Exit(1)
		}
	} else {
		fmt.Println("Source is missing")
		return
	}
	defer handle.Close()

	img := image.NewNRGBA(image.Rect(0, 0, 512, int(*num)))

	if len(*filter) != 0 {
		err = handle.SetBPFFilter(*filter)
		if err != nil {
			log.Fatal(err, "\tInvalid filter: ", *filter)
			os.Exit(1)
		}
	}

	packetSource := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	packetSource.DecodeOptions = gopacket.Lazy

	handlePackets(packetSource, img, *num)

	f, err := os.Create(*output)
	if err != nil {
		log.Fatal(err)
	}

	if err := png.Encode(f, img); err != nil {
		f.Close()
		log.Fatal(err)
	}

	if err := f.Close(); err != nil {
		log.Fatal(err)
	}
}
