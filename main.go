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
	"os/signal"
	"strconv"
)

const Version = "0.0.1"

type Data struct {
	toa     int64
	payload []byte
}

func createVisualization(data []Data, xMax int, prefix string, num int) {

	img := image.NewNRGBA(image.Rect(0, 0, xMax/3+1, len(data)))

	for i := range data {
		var j int
		for j = 0; j+3 <= len(data[i].payload); j += 3 {
			img.Set(j/3, i, color.NRGBA{
				R: uint8(data[i].payload[j]),
				G: uint8(data[i].payload[j+1]),
				B: uint8(data[i].payload[j+2]),
				A: 255})
		}
		switch len(data[i].payload) - j {
		case 2:
			img.Set(j/3, i, color.NRGBA{
				R: uint8(data[i].payload[j]),
				G: uint8(data[i].payload[j+1]),
				B: uint8(0),
				A: 255})
		case 1:
			img.Set(j/3, i, color.NRGBA{
				R: uint8(data[i].payload[j]),
				G: uint8(0),
				B: uint8(0),
				A: 255})
		default:
		}
	}

	filename := prefix
	filename += strconv.Itoa(num)
	filename += ".png"
	f, err := os.Create(filename)
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

	return
}

func handlePackets(ps *gopacket.PacketSource, num uint, ch chan Data, sig <-chan os.Signal) {
	var count uint
	for packet := range ps.Packets() {
		var k Data
		if <-sig == os.Interrupt {
			close(ch)
			return
		}
		count++
		if count != 0 && count > num {
			break
		}

		elements := packet.Data()
		if len(elements) == 0 {
			continue
		}
		k = Data{toa: packet.Metadata().CaptureInfo.Timestamp.UnixNano(), payload: packet.Data()}
		ch <- k
	}
	close(ch)
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
	var data []Data
	var xMax int
	var index int = 1
	ch := make(chan Data)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	dev := flag.String("interface", "", "Choose an interface for online processing")
	file := flag.String("file", "", "Choose a file for offline processing")
	filter := flag.String("filter", "", "Set a specific filter")
	lst := flag.Bool("list_interfaces", false, "List available interfaces")
	vers := flag.Bool("version", false, "Show version")
	help := flag.Bool("help", false, "Show this help")
	num := flag.Uint("count", 25, "Number of packets to process.\n\tIf argument is 0 the limit is removed")
	output := flag.String("prefix", "image", "Prefix of the resulting image")
	size := flag.Uint("size", 25, "Number of packets per image")
	flag.Parse()

	if flag.NFlag() < 1 {
		flag.PrintDefaults()
		return
	}

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

	if len(*filter) != 0 {
		err = handle.SetBPFFilter(*filter)
		if err != nil {
			log.Fatal(err, "\tInvalid filter: ", *filter)
			os.Exit(1)
		}
	}

	packetSource := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	packetSource.DecodeOptions = gopacket.Lazy

	go handlePackets(packetSource, *num, ch, sig)

	for i := range ch {
		data = append(data, i)
		if xMax < len(i.payload) {
			xMax = len(i.payload)
		}
		if len(data) >= int(*size) {
			xMax++
			createVisualization(data, xMax, *output, index)
			xMax = 0
			index++
			data = data[:0]
		}
	}
	if len(data) > 0 {
		xMax++
		createVisualization(data, xMax, *output, index)
	}

}
