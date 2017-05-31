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
	"time"
)

const Version = "0.0.2"

type Data struct {
	toa     int64 // Timestamp in microseconds
	payload []byte
}

func getBitsFromPacket(packet []byte, byteP, bitP *int, bpP int) uint8 {
	var c uint8
	for i := 0; i < (bpP / 3); i++ {
		if *byteP >= len(packet) {
			break
		}
		c |= (packet[*byteP] & (1 << uint8(7-*bitP)))
		*bitP += 1
		if *bitP%8 == 0 {
			*bitP = 0
			*byteP += 1
		}
	}
	return c
}

func createPixel(packet []byte, byteP, bitP *int, bpP int) (c color.Color) {
	var r, g, b uint8

	if bpP == 1 {
		if (packet[*byteP] & (1 << uint8(7-*bitP))) == 0 {
			c = color.NRGBA{R: 0,
				G: 0,
				B: 0,
				A: 255}
		} else {
			c = color.NRGBA{R: 255,
				G: 255,
				B: 255,
				A: 255}
		}
		*bitP += 1
		if *bitP%8 == 0 {
			*bitP = 0
			*byteP += 1
		}
	} else {
		r = getBitsFromPacket(packet, byteP, bitP, bpP)
		g = getBitsFromPacket(packet, byteP, bitP, bpP)
		b = getBitsFromPacket(packet, byteP, bitP, bpP)

		c = color.NRGBA{R: r,
			G: g,
			B: b,
			A: 255}
	}
	return
}

func createTerminalVisualization(data []Data, bitsPerPixel int) {
	var bitPos int
	var bytePos int
	var packetLen int

	for i := range data {
		packetLen = len(data[i].payload)
		bitPos = 0
		bytePos = 0
		for {
			c := createPixel(data[i].payload, &bytePos, &bitPos, bitsPerPixel)
			r, g, b, _ := c.RGBA()
			fmt.Printf("\x1B[0m\x1B[38;2;%d;%d;%dm\u2588", uint8(r), uint8(g), uint8(b))
			if bytePos >= packetLen {
				break
			}
		}
		fmt.Printf("\x1B[m\n")

	}

}
func createTimeVisualization(data []Data, xMax int, prefix string, ts uint, bitsPerPixel int) {
	var xPos int
	var bitPos int
	var bytePos int
	var packetLen int
	var firstPkg time.Time

	img := image.NewNRGBA(image.Rect(0, 0, (xMax*8)/bitsPerPixel+1, int(ts)))

	for pkg := range data {
		if firstPkg.IsZero() {
			firstPkg = time.Unix(0, data[pkg].toa*int64(time.Microsecond))
		}
		packetLen = len(data[pkg].payload)
		xPos = 0
		bitPos = 0
		bytePos = 0
		for {
			c := createPixel(data[pkg].payload, &bytePos, &bitPos, bitsPerPixel)
			img.Set(xPos, int(data[pkg].toa%int64(ts)), c)
			xPos++
			if bytePos >= packetLen {
				break
			}
		}
	}

	filename := prefix
	filename += "-"
	filename += firstPkg.Format(time.RFC3339Nano)
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

func createFixedVisualization(data []Data, xMax int, prefix string, num int, bitsPerPixel int) {
	var xPos int
	var bitPos int
	var bytePos int
	var packetLen int

	img := image.NewNRGBA(image.Rect(0, 0, (xMax*8)/bitsPerPixel+1, len(data)))

	for yPos := range data {
		packetLen = len(data[yPos].payload)
		xPos = 0
		bitPos = 0
		bytePos = 0
		for {
			c := createPixel(data[yPos].payload, &bytePos, &bitPos, bitsPerPixel)
			img.Set(xPos, yPos, c)
			xPos++
			if bytePos >= packetLen {
				break
			}
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

		select {
		case isr := <-sig:
			fmt.Println(isr)
			close(ch)
			return
		default:
		}
		count++
		if num != 0 && count > num {
			break
		}

		elements := packet.Data()
		if len(elements) == 0 {
			continue
		}
		k = Data{toa: (packet.Metadata().CaptureInfo.Timestamp.UnixNano() / int64(time.Microsecond)), payload: packet.Data()}
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
	var slicer int64
	var flagTimeslize bool = false
	ch := make(chan Data)
	sig := make(chan os.Signal)
	signal.Notify(sig, os.Interrupt)

	dev := flag.String("interface", "", "Choose an interface for online processing")
	file := flag.String("file", "", "Choose a file for offline processing")
	filter := flag.String("filter", "", "Set a specific filter")
	lst := flag.Bool("list_interfaces", false, "List available interfaces")
	vers := flag.Bool("version", false, "Show version")
	help := flag.Bool("help", false, "Show this help")
	terminalOut := flag.Bool("terminal", false, "Visualize on terminal")
	num := flag.Uint("count", 25, "Number of packets to process.\n\tIf argument is 0 the limit is removed")
	output := flag.String("prefix", "image", "Prefix of the resulting image")
	size := flag.Uint("size", 25, "Number of packets per image")
	bits := flag.Uint("bits", 24, "Number of bits per pixel.\n\tIt must be divisible by three and smaller than 25\n\tTo get black/white results, choose 1 as input.")
	ts := flag.Uint("timeslize", 0, "Number of microseconds per resulting image.\n\tSo each pixel of the height of the resulting image represents one microsecond")
	flag.Parse()

	if flag.NFlag() < 1 {
		fmt.Println(os.Args[0], "[-bits ...] [-count ...] [-file ... | -interface ...] [-filter ...] [-list_interfaces] [-help] [-prefix ...] [-size ... | -timeslize ... | -terminal] [-version]")
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

	if *bits%3 != 0 && *bits != 1 {
		fmt.Println(*bits, "must be divisible by three or one")
		return
	} else if *bits > 25 {
		fmt.Println(*bits, "must be smaller than 25")
		return
	}

	if *ts != 0 {
		flagTimeslize = true
	}

	if *help {
		fmt.Println(os.Args[0], "[-bits ...] [-count ...] [-file ... | -interface ...] [-filter ...] [-list_interfaces] [-help] [-prefix ...] [-size ... | -timeslize ... | -terminal] [-version]")
		flag.PrintDefaults()
		return
	}

	switch {
	case flagTimeslize == true && *terminalOut:
		fmt.Println("-timeslize and -terminal can't be combined")

		fmt.Println(os.Args[0], "[-bits ...] [-count ...] [-file ... | -interface ...] [-filter ...] [-list_interfaces] [-help] [-prefix ...] [-size ... | -timeslize ... | -terminal] [-version]")
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

	switch {
	case flagTimeslize:
		for i, ok := <-ch; ok; i, ok = <-ch {
			if slicer == 0 {
				slicer = i.toa + int64(*ts)
			}
			if slicer < i.toa {
				xMax++
				createTimeVisualization(data, xMax, *output, *ts, int(*bits))
				xMax = 0
				data = data[:0]
				slicer = i.toa + int64(*ts)
			}
			data = append(data, i)
			if xMax < len(i.payload) {
				xMax = len(i.payload)
			}
		}
	case *terminalOut:
		for i, ok := <-ch; ok; i, ok = <-ch {
			data = append(data, i)
			createTerminalVisualization(data, int(*bits))
			data = data[:0]
		}
	default:
		for i, ok := <-ch; ok; i, ok = <-ch {
			data = append(data, i)
			if xMax < len(i.payload) {
				xMax = len(i.payload)
			}
			if len(data) >= int(*size) {
				xMax++
				createFixedVisualization(data, xMax, *output, index, int(*bits))
				xMax = 0
				index++
				data = data[:0]
			}
		}
	}

	if len(data) > 0 {
		xMax++
		if flagTimeslize {
			createTimeVisualization(data, xMax, *output, *ts, int(*bits))
		} else {
			createFixedVisualization(data, xMax, *output, index, int(*bits))
		}
	}

}