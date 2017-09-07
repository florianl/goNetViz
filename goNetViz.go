package main

import (
	"bytes"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"os"
	"os/signal"
	"strconv"
	"time"
)

const (
	SOLDER     = 0x01
	TERMINAL   = 0x02
	TIMESLIZES = 0x04
)

// Version number of this tool
const Version = "0.0.2"

// Data is a struct for each network packet
type Data struct {
	toa     int64  // Timestamp of arrival in microseconds
	payload []byte // Copied network packet
}

// configs represents all the configuration data
type configs struct {
	bpP   uint // Bits per Pixel
	ppI   uint // Number of packets per Image
	ts    uint // "Duration" for one Image
	limit uint // Number of network packets to process
	stil  uint // Type of illustration
	scale uint // Scaling factor for output
}

func getBitsFromPacket(packet []byte, byteP, bitP *int, bpP uint) uint8 {
	var c uint8
	for i := 0; i < (int(bpP) / 3); i++ {
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

func createPixel(packet []byte, byteP, bitP *int, bpP uint) (uint8, uint8, uint8) {
	var r, g, b uint8

	if bpP == 1 {
		if (packet[*byteP] & (1 << uint8(7-*bitP))) == 0 {
			return 0, 0, 0
		} else {
			return 255, 255, 255
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
	}

	return r, g, b
}

func createTerminalVisualization(pkt1 Data, pkt2 Data, bitsPerPixel uint) {
	var bitPos, cpyBitPos int
	var bytePos, cpyBytePos int
	var pkt1Len, pkt2Len int

	pkt1Len = len(pkt1.payload)
	pkt2Len = len(pkt2.payload)
	bitPos = 0
	bytePos = 0
	for {
		if bytePos >= pkt1Len {
			r2, g2, b2 := createPixel(pkt2.payload, &bytePos, &bitPos, bitsPerPixel)
			fmt.Printf("\x1B[38;2;%d;%d;%dm\u2580", uint8(r2), uint8(g2), uint8(b2))
		} else if bytePos >= pkt2Len {
			r1, g1, b1 := createPixel(pkt1.payload, &bytePos, &bitPos, bitsPerPixel)
			fmt.Printf("\x1B[38;2;%d;%d;%dm\u2580", uint8(r1), uint8(g1), uint8(b1))
		} else {
			cpyBitPos = bitPos
			cpyBytePos = bytePos
			r1, g1, b1 := createPixel(pkt1.payload, &cpyBytePos, &cpyBitPos, bitsPerPixel)
			r2, g2, b2 := createPixel(pkt2.payload, &bytePos, &bitPos, bitsPerPixel)
			fmt.Printf("\x1B[48;2;%d;%d;%dm\x1B[38;2;%d;%d;%dm\u2580", uint8(r2), uint8(g2), uint8(b2), uint8(r1), uint8(g1), uint8(b1))
		}
		if bytePos >= pkt1Len && bytePos >= pkt2Len {
			break
		}
	}
	fmt.Printf("\x1B[m\n")

}

func createImage(filename string, width, height int, data string) error {
	if len(data) == 0 {
		return fmt.Errorf("No image data provided")
	}

	f, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return fmt.Errorf("Could not open image: %s", err)
	}

	if _, err := f.WriteString(fmt.Sprintf("<?xml version=\"1.0\"?>\n<svg width=\"%d\" height=\"%d\">\n", width, height)); err != nil {
		f.Close()
		return fmt.Errorf("Could not write image: %s", err)
	}

	if _, err := f.WriteString(data); err != nil {
		f.Close()
		return fmt.Errorf("Could not write image: %s", err)
	}

	if _, err := f.WriteString("</svg>"); err != nil {
		f.Close()
		return fmt.Errorf("Could not write image: %s", err)
	}

	if err := f.Close(); err != nil {
		return fmt.Errorf("Could not close image: %s", err)
	}

	return nil
}

func createTimeVisualization(data []Data, xMax int, prefix string, ts uint, config configs) error {
	var xPos, yPos int
	var bitPos int
	var bytePos int
	var packetLen int
	var firstPkg time.Time
	var svg bytes.Buffer
	var bitsPerPixel int = int(config.bpP)
	var scale int = int(config.scale)

	for pkg := range data {
		if firstPkg.IsZero() {
			firstPkg = time.Unix(0, data[pkg].toa*int64(time.Microsecond))
		}
		packetLen = len(data[pkg].payload)
		xPos = 0
		bitPos = 0
		bytePos = 0
		for {
			r, g, b := createPixel(data[pkg].payload, &bytePos, &bitPos, uint(bitsPerPixel))
			fmt.Fprintf(&svg, "<rect x=\"%d\" y=\"%d\" width=\"%d\" height=\"%d\" style=\"fill:rgb(%d,%d,%d)\" />\n", xPos*scale, yPos*scale, scale, scale, uint8(r), uint8(g), uint8(b))
			xPos++
			if bytePos >= packetLen {
				break
			}
		}
	}

	filename := prefix
	filename += "-"
	filename += firstPkg.Format(time.RFC3339Nano)
	filename += ".svg"

	return createImage(filename, ((xMax*8)/int(bitsPerPixel)+1)*scale, (yPos+1)*scale, svg.String())
}

func createFixedVisualization(data []Data, xMax int, prefix string, num int, config configs) error {
	var xPos, yPos int
	var bitPos int
	var bytePos int
	var packetLen int
	var svg bytes.Buffer
	var bitsPerPixel int = int(config.bpP)
	var scale int = int(config.scale)

	for yPos = range data {
		packetLen = len(data[yPos].payload)
		xPos = 0
		bitPos = 0
		bytePos = 0
		for {
			r, g, b := createPixel(data[yPos].payload, &bytePos, &bitPos, uint(bitsPerPixel))
			fmt.Fprintf(&svg, "<rect x=\"%d\" y=\"%d\" width=\"%d\" height=\"%d\" style=\"fill:rgb(%d,%d,%d)\" />\n", xPos*scale, yPos*scale, scale, scale, uint8(r), uint8(g), uint8(b))
			xPos++
			if bytePos >= packetLen {
				break
			}
		}

	}

	filename := prefix
	filename += strconv.Itoa(num)
	filename += ".svg"

	return createImage(filename, ((xMax*8)/bitsPerPixel+1)*scale, (yPos+1)*scale, svg.String())
}

func handlePackets(ps *gopacket.PacketSource, num uint, ch chan<- Data, done <-chan os.Signal) {
	var count uint
	for packet := range ps.Packets() {
		var k Data
		select {
		case <-done:
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

func availableInterfaces() error {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return fmt.Errorf("%s", err)
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
	return nil
}

func initSource(dev, file *string, filter *string) (handle *pcap.Handle, err error) {
	if len(*dev) > 0 {
		handle, err = pcap.OpenLive(*dev, 4096, true, pcap.BlockForever)
		if err != nil {
			return nil, fmt.Errorf("%s", err)
		}
	} else if len(*file) > 0 {
		handle, err = pcap.OpenOffline(*file)
		if err != nil {
			return nil, fmt.Errorf("%s", err)
		}
	} else {
		return nil, fmt.Errorf("Source is missing\n")
	}

	if len(*filter) != 0 {
		err = handle.SetBPFFilter(*filter)
		if err != nil {
			return nil, fmt.Errorf("%s\nInvalid Filter: %s", err, *filter)
		}
	}

	return
}

func checkConfig(cfg *configs) error {
	if cfg.bpP%3 != 0 && cfg.bpP != 1 {
		return fmt.Errorf("-bits %d is not divisible by three or one", cfg.bpP)
	} else if cfg.bpP > 25 {
		return fmt.Errorf("-bits %d must be smaller than 25", cfg.bpP)
	}

	if cfg.ts > 0 {
		cfg.stil |= TIMESLIZES
	}

	if cfg.stil == (TIMESLIZES | TERMINAL) {
		return fmt.Errorf("-timeslize and -terminal can't be combined")
	} else if cfg.stil == 0 {
		cfg.stil |= SOLDER
	}

	if cfg.stil == TERMINAL && cfg.scale != 1 {
		return fmt.Errorf("-scale and -terminal can't be combined")
	}

	if cfg.scale == 0 {
		return fmt.Errorf("scale factor has to be at least 1")
	}

	return nil
}

func main() {
	var err error
	var handle *pcap.Handle
	var data []Data
	var xMax int
	var index int = 1
	osSig := make(chan os.Signal, 1)
	signal.Notify(osSig, os.Interrupt)
	var slicer int64
	var cfg configs
	ch := make(chan Data)

	dev := flag.String("interface", "", "Choose an interface for online processing.")
	file := flag.String("file", "", "Choose a file for offline processing.")
	filter := flag.String("filter", "", "Set a specific filter.")
	lst := flag.Bool("list_interfaces", false, "List available interfaces.")
	vers := flag.Bool("version", false, "Show version.")
	help := flag.Bool("help", false, "Show this help.")
	terminalOut := flag.Bool("terminal", false, "Visualize output on terminal.")
	num := flag.Uint("count", 25, "Number of packets to process.\n\tIf argument is 0 the limit is removed.")
	prefix := flag.String("prefix", "image", "Prefix of the resulting image.")
	size := flag.Uint("size", 25, "Number of packets per image.")
	bits := flag.Uint("bits", 24, "Number of bits per pixel. It must be divisible by three and smaller than 25 or 1.\n\tTo get black/white results, choose 1 as input.")
	ts := flag.Uint("timeslize", 0, "Number of microseconds per resulting image.\n\tSo each pixel of the height of the resulting image represents one microsecond.")
	scale := flag.Uint("scale", 1, "Scaling factor for output.\n\tWorks not for output on terminal.")
	flag.Parse()

	if *lst {
		err = availableInterfaces()
		if err != nil {
			fmt.Println("Could not list interfaces:", err)
		}
		return
	}

	if *vers {
		fmt.Println("Version:", Version)
		return
	}

	if *help || len(os.Args) < 2 {
		fmt.Println(os.Args[0], "[-bits ...] [-count ...] [-file ... | -interface ...] [-filter ...] [-list_interfaces] [-help] [-prefix ...] [-scale ...] [-size ... | -timeslize ... | -terminal] [-version]")
		flag.PrintDefaults()
		return
	}

	cfg.bpP = *bits
	cfg.ppI = *size
	cfg.ts = *ts
	cfg.limit = *num
	cfg.stil = 0
	cfg.scale = *scale

	if *terminalOut == true {
		cfg.stil |= TERMINAL
	}

	if err = checkConfig(&cfg); err != nil {
		fmt.Println("Configuration error:", err)
		return
	}

	handle, err = initSource(dev, file, filter)
	if err != nil {
		fmt.Println("Could not open source:", err)
		return
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	packetSource.DecodeOptions = gopacket.Lazy

	go handlePackets(packetSource, cfg.limit, ch, osSig)

	switch cfg.stil {
	case SOLDER:
		for i, ok := <-ch; ok; i, ok = <-ch {
			data = append(data, i)
			if xMax < len(i.payload) {
				xMax = len(i.payload)
			}
			if len(data) >= int(cfg.ppI) {
				xMax++
				createFixedVisualization(data, xMax, *prefix, index, cfg)
				xMax = 0
				index++
				data = data[:0]
			}
		}
	case TERMINAL:
		for i, ok := <-ch; ok; i, ok = <-ch {
			var j Data
			j, ok = <-ch
			if !ok {
				createTerminalVisualization(i, Data{toa: 0, payload: nil}, cfg.bpP)
				break
			} else {
				createTerminalVisualization(i, j, cfg.bpP)
			}
		}
	case TIMESLIZES:
		for i, ok := <-ch; ok; i, ok = <-ch {
			if slicer == 0 {
				slicer = i.toa + int64(*ts)
			}
			if slicer < i.toa {
				xMax++
				createTimeVisualization(data, xMax, *prefix, *ts, cfg)
				xMax = 0
				data = data[:0]
				slicer = i.toa + int64(*ts)
			}
			data = append(data, i)
			if xMax < len(i.payload) {
				xMax = len(i.payload)
			}
		}
	}

	if len(data) > 0 {
		xMax++
		switch cfg.stil {
		case SOLDER:
			createFixedVisualization(data, xMax, *prefix, index, cfg)
		case TIMESLIZES:
			createTimeVisualization(data, xMax, *prefix, *ts, cfg)
		}
	}

}
