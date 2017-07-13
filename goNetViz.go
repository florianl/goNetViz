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

func createPixel(packet []byte, byteP, bitP *int, bpP uint) (c color.Color) {
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

func createTerminalVisualization(data Data, bitsPerPixel uint) {
	var bitPos int
	var bytePos int
	var packetLen int

	packetLen = len(data.payload)
	bitPos = 0
	bytePos = 0
	for {
		c := createPixel(data.payload, &bytePos, &bitPos, bitsPerPixel)
		r, g, b, _ := c.RGBA()
		fmt.Printf("\x1B[0m\x1B[38;2;%d;%d;%dm\u2588", uint8(r), uint8(g), uint8(b))
		if bytePos >= packetLen {
			break
		}
	}
	fmt.Printf("\x1B[m\n")

}
func createTimeVisualization(data []Data, xMax int, prefix string, ts uint, bitsPerPixel uint) {
	var xPos int
	var bitPos int
	var bytePos int
	var packetLen int
	var firstPkg time.Time

	img := image.NewNRGBA(image.Rect(0, 0, (xMax*8)/int(bitsPerPixel)+1, int(ts)))

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
		fmt.Errorf("%s", err)
		return
	}

	if err := png.Encode(f, img); err != nil {
		f.Close()
		fmt.Errorf("%s", err)
	}

	if err := f.Close(); err != nil {
		fmt.Errorf("%s", err)
	}

	return
}

func createFixedVisualization(data []Data, xMax int, prefix string, num int, bitsPerPixel uint) {
	var xPos int
	var bitPos int
	var bytePos int
	var packetLen int

	img := image.NewNRGBA(image.Rect(0, 0, (xMax*8)/int(bitsPerPixel)+1, len(data)))

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
		fmt.Errorf("%s", err)
		return
	}

	if err := png.Encode(f, img); err != nil {
		f.Close()
		fmt.Errorf("%s", err)
	}

	if err := f.Close(); err != nil {
		fmt.Errorf("%s", err)
	}

	return
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

func availableInterfaces() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		fmt.Errorf("%s", err)
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

func initSource(dev, file *string) (handle *pcap.Handle, err error) {
	if len(*dev) > 0 {
		handle, err = pcap.OpenLive(*dev, 4096, true, pcap.BlockForever)
		if err != nil {
			fmt.Errorf("%s", err)
			os.Exit(1)
		}
	} else if len(*file) > 0 {
		handle, err = pcap.OpenOffline(*file)
		if err != nil {
			fmt.Errorf("%s", err)
			os.Exit(1)
		}
	} else {
		return nil, fmt.Errorf("Source is missing\n")
	}
	return
}

func checkConfig(cfg configs) error {
	if cfg.bpP%3 != 0 && cfg.bpP != 1 {
		return fmt.Errorf("%d must be divisible by three or should be one", cfg.bpP)
	} else if cfg.bpP > 25 {
		return fmt.Errorf("%d must be smaller than 25", cfg.bpP)
	}

	if cfg.ts > 0 {
		cfg.stil |= TIMESLIZES
	}

	if cfg.stil == (TIMESLIZES | TERMINAL) {
		return fmt.Errorf("-timeslize and -terminal can't be combined")
	} else if cfg.stil == 0 {
		// If way of stil is provided, we will stick to the default one
		cfg.stil |= SOLDER
	}
	return nil
}

func init() {
	if len(os.Args) < 2 {
		fmt.Println(os.Args[0], "[-bits ...] [-count ...] [-file ... | -interface ...] [-filter ...] [-list_interfaces] [-help] [-prefix ...] [-size ... | -timeslize ... | -terminal] [-version]")
		flag.PrintDefaults()
		os.Exit(1)
	}
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

	if *lst {
		availableInterfaces()
		return
	}

	if *vers {
		fmt.Println("Version:", Version)
		return
	}

	if *help {
		fmt.Println(os.Args[0], "[-bits ...] [-count ...] [-file ... | -interface ...] [-filter ...] [-list_interfaces] [-help] [-prefix ...] [-size ... | -timeslize ... | -terminal] [-version]")
		flag.PrintDefaults()
		return
	}

	cfg.bpP = *bits
	cfg.ppI = *size
	cfg.ts = *ts
	cfg.limit = *num
	cfg.stil = 0

	if *terminalOut == true {
		cfg.stil |= TERMINAL
	}
	if *ts != 0 {
		cfg.stil |= TIMESLIZES
	}

	if err = checkConfig(cfg); err != nil {
		fmt.Errorf("%s", err)
		os.Exit(1)
	}

	handle, err = initSource(dev, file)
	if err != nil {
		fmt.Errorf("%s", err)
		os.Exit(1)
	}
	defer handle.Close()

	if len(*filter) != 0 {
		err = handle.SetBPFFilter(*filter)
		if err != nil {
			fmt.Errorf("%s\nInvalid Filter: %s", err, *filter)
			os.Exit(1)
		}
	}

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
			if len(data) >= int(*size) {
				xMax++
				createFixedVisualization(data, xMax, *output, index, cfg.bpP)
				xMax = 0
				index++
				data = data[:0]
			}
		}
	case TERMINAL:
		for i, ok := <-ch; ok; i, ok = <-ch {
			createTerminalVisualization(i, cfg.bpP)
		}
	case TIMESLIZES:
		for i, ok := <-ch; ok; i, ok = <-ch {
			if slicer == 0 {
				slicer = i.toa + int64(*ts)
			}
			if slicer < i.toa {
				xMax++
				createTimeVisualization(data, xMax, *output, *ts, cfg.bpP)
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
			createFixedVisualization(data, xMax, *output, index, cfg.bpP)
		case TIMESLIZES:
			createTimeVisualization(data, xMax, *output, *ts, cfg.bpP)
		}
	}

}
