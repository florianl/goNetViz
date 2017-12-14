package main

import (
	"bufio"
	"bytes"
	"context"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"golang.org/x/sync/errgroup"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"time"
)

const (
	solder    = 0x01
	terminal  = 0x02
	timeslize = 0x04
	reverse   = 0x08
)

// Version number of this tool
const Version = "0.0.3"

// Data is a struct for each network packet
type data struct {
	toa     int64  // Timestamp of arrival in microseconds
	payload []byte // Copied network packet
}

// configs represents all the configuration data
type configs struct {
	bpP    uint   // Bits per Pixel
	ppI    uint   // Number of packets per Image
	ts     int64  // "Duration" for one Image
	limit  uint   // Number of network packets to process
	stil   uint   // Type of illustration
	scale  uint   // Scaling factor for output
	xlimit uint   // Limit of bytes per packet
	dev    string // network interface as source of visualization
	filter string // filter for the network interface
	file   string //  file as source of visualization
	prefix string // prefix for the visualization results
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
			r, g, b = uint8(0), uint8(0), uint8(0)
		} else {
			r, g, b = uint8(255), uint8(255), uint8(255)
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

func createTerminalVisualization(pkt1, pkt2 data, cfg configs) {
	var bit1Pos, bit2Pos int
	var byte1Pos, byte2Pos int
	var pkt1Len, pkt2Len int
	var r1, g1, b1 uint8
	var r2, g2, b2 uint8
	var bitsPerPixel = uint(cfg.bpP)

	pkt1Len = len(pkt1.payload)
	pkt2Len = len(pkt2.payload)

	if pkt1Len == 0 {
		pkt1Len = -1
	}
	if pkt2Len == 0 {
		pkt2Len = -1
	}

	for {
		if byte1Pos > pkt1Len {
			r1, g1, b1 = 0x00, 0x00, 0x00
			r2, g2, b2 = createPixel(pkt2.payload, &byte2Pos, &bit2Pos, bitsPerPixel)
			fmt.Printf("\x1B[38;2;%d;%d;%dm\x1B[48;2;%d;%d;%dm\u2584", r2, g2, b2, r1, g1, b1)
		} else if byte2Pos > pkt2Len {
			r1, g1, b1 = createPixel(pkt1.payload, &byte1Pos, &bit1Pos, bitsPerPixel)
			r2, g2, b2 = 0x00, 0x00, 0x00
			fmt.Printf("\x1B[48;2;%d;%d;%dm\x1B[38;2;%d;%d;%dm\u2580", r2, g2, b2, r1, g1, b1)
		} else {
			r1, g1, b1 = createPixel(pkt1.payload, &byte1Pos, &bit1Pos, bitsPerPixel)
			r2, g2, b2 = createPixel(pkt2.payload, &byte2Pos, &bit2Pos, bitsPerPixel)
			fmt.Printf("\x1B[48;2;%d;%d;%dm\x1B[38;2;%d;%d;%dm\u2580", r2, g2, b2, r1, g1, b1)
		}
		if byte1Pos >= pkt1Len && byte2Pos >= pkt2Len {
			break
		}
		if byte1Pos >= int(cfg.xlimit) || byte2Pos >= int(cfg.xlimit) {
			break
		}
	}
	fmt.Printf("\x1B[m\n")

}

func createImage(filename string, width, height int, content string, scale int, bitsPerPixel int) error {
	if len(content) == 0 {
		return fmt.Errorf("No content to write")
	}

	f, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return fmt.Errorf("Could not open file %s: %s", filename, err.Error())
	}

	if _, err := f.WriteString(fmt.Sprintf("<?xml version=\"1.0\"?>\n<svg width=\"%d\" height=\"%d\">\n", width, height)); err != nil {
		f.Close()
		return fmt.Errorf("Could not write header: %s", err.Error())
	}

	if _, err := f.WriteString(fmt.Sprintf("<!--\n\tgoNetViz \"%s\"\n\tScale=%d\n\tBitsPerPixel=%d\n-->\n",
		Version, scale, bitsPerPixel)); err != nil {
		f.Close()
		return fmt.Errorf("Could not write additional information: %s", err.Error())
	}

	if _, err := f.WriteString(content); err != nil {
		f.Close()
		return fmt.Errorf("Could not write content: %s", err.Error())
	}

	if _, err := f.WriteString("</svg>"); err != nil {
		f.Close()
		return fmt.Errorf("Could not write closing information: %s", err.Error())
	}

	if err := f.Close(); err != nil {
		return fmt.Errorf("Could not close file %s: %s", filename, err.Error())
	}
	return nil
}

func createVisualization(g *errgroup.Group, content []data, num uint, cfg configs) {
	var xPos int
	var yPos int = -1
	var bitPos int
	var bytePos int
	var packetLen int
	var firstPkg time.Time
	var svg bytes.Buffer
	var bitsPerPixel int = int(cfg.bpP)
	var scale int = int(cfg.scale)
	var xLimit uint = cfg.xlimit
	var prefix string = cfg.prefix
	var xMax int

	for pkg := range content {
		if firstPkg.IsZero() {
			firstPkg = time.Unix(0, content[pkg].toa*int64(time.Microsecond))
		}
		packetLen = len(content[pkg].payload)
		xPos = 0
		if cfg.stil == solder {
			yPos += 1
		} else {
			current := time.Unix(0, content[pkg].toa*int64(time.Microsecond))
			yPos = int(current.Sub(firstPkg))
		}
		bitPos = 0
		bytePos = 0
		for {
			r, g, b := createPixel(content[pkg].payload, &bytePos, &bitPos, uint(bitsPerPixel))
			fmt.Fprintf(&svg, "<rect x=\"%d\" y=\"%d\" width=\"%d\" height=\"%d\" style=\"fill:rgb(%d,%d,%d)\" />\n", xPos*scale, yPos*scale, scale, scale, uint8(r), uint8(g), uint8(b))
			xPos++
			if bytePos >= packetLen {
				break
			}
			if xPos > xMax {
				xMax = xPos
			}
			if xPos >= int(xLimit) && xLimit != 0 {
				break
			}
		}
	}

	filename := prefix
	filename += "-"
	if cfg.stil == timeslize {
		filename += firstPkg.Format(time.RFC3339Nano)
	} else {
		filename += fmt.Sprint(num)
	}
	filename += ".svg"

	g.Go(func() error {
		return createImage(filename, (xMax+1)*scale, (yPos+1)*scale, svg.String(), scale, bitsPerPixel)
	})
}

func handlePackets(g *errgroup.Group, ps *gopacket.PacketSource, num uint, ch chan<- data) {
	var count uint
	for packet := range ps.Packets() {
		count++
		if num != 0 && count > num {
			break
		}

		elements := packet.Data()
		if len(elements) == 0 {
			continue
		}
		ch <- data{toa: (packet.Metadata().CaptureInfo.Timestamp.UnixNano() / int64(time.Microsecond)), payload: packet.Data()}
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

func initSource(dev, file, filter string) (handle *pcap.Handle, err error) {
	if len(dev) > 0 {
		handle, err = pcap.OpenLive(dev, 4096, true, -10*time.Microsecond)
		if err != nil {
			return nil, fmt.Errorf("%s", err)
		}
	} else if len(file) > 0 {
		handle, err = pcap.OpenOffline(file)
		if err != nil {
			return nil, fmt.Errorf("%s", err)
		}
	} else {
		return nil, fmt.Errorf("Source is missing\n")
	}

	if len(filter) != 0 {
		err = handle.SetBPFFilter(filter)
		if err != nil {
			return nil, fmt.Errorf("%s\nInvalid Filter: %s", err, filter)
		}
	}

	return
}

func checkConfig(cfg *configs, console, rebuild bool) error {

	if console {
		cfg.stil |= terminal
	}

	if rebuild {
		cfg.stil |= reverse
	}

	if cfg.bpP%3 != 0 && cfg.bpP != 1 {
		return fmt.Errorf("-bits %d is not divisible by three or one", cfg.bpP)
	} else if cfg.bpP > 25 {
		return fmt.Errorf("-bits %d must be smaller than 25", cfg.bpP)
	}

	if cfg.ts > 0 {
		cfg.stil |= timeslize
	}

	switch cfg.stil {
	case (timeslize | terminal):
		return fmt.Errorf("-timeslize and -terminal can't be combined")
	case (timeslize | reverse):
		return fmt.Errorf("-timeslize and -reverse can't be combined")
	case (terminal | reverse):
		return fmt.Errorf("-terminal and -reverse can't be combined")
	case (terminal | timeslize | reverse):
		return fmt.Errorf("-terminal, -timeslize and -reverse can't be combined")
	case 0: /*	no specific option was given	*/
		cfg.stil |= solder
	}

	if cfg.stil == reverse && len(cfg.file) == 0 {
		return fmt.Errorf("-file is needed as source")
	}

	if cfg.stil == terminal && cfg.scale != 1 {
		return fmt.Errorf("-scale and -terminal can't be combined")
	}

	if cfg.scale == 0 {
		return fmt.Errorf("scale factor has to be at least 1")
	}

	if cfg.xlimit > 9000 {
		return fmt.Errorf("limit has to be smallerthan a Jumbo frame (9000 bytes)")
	}

	return nil
}

func visualize(g *errgroup.Group, cfg configs) error {
	ch := make(chan data)
	var content []data
	var index uint = 1
	var slicer int64

	handle, err := initSource(cfg.dev, cfg.file, cfg.filter)
	if err != nil {
		return err
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	packetSource.DecodeOptions = gopacket.Lazy

	go handlePackets(g, packetSource, cfg.limit, ch)

	switch cfg.stil {
	case solder:
		for i, ok := <-ch; ok; i, ok = <-ch {
			content = append(content, i)
			if len(content) >= int(cfg.ppI) {
				createVisualization(g, content, index, cfg)
				index++
				content = content[:0]
			}
		}
	case terminal:
		for i, ok := <-ch; ok; i, ok = <-ch {
			var j data
			j, ok = <-ch
			if !ok {
				createTerminalVisualization(i, data{toa: 0, payload: nil}, cfg)
				break
			} else {
				createTerminalVisualization(i, j, cfg)
			}
		}
	case timeslize:
		for i, ok := <-ch; ok; i, ok = <-ch {
			if slicer == 0 {
				slicer = i.toa + int64(cfg.ts)
			}
			if slicer < i.toa {
				createVisualization(g, content, 0, cfg)
				content = content[:0]
				slicer = i.toa + int64(cfg.ts)
			}
			content = append(content, i)
		}
	}

	if len(content) > 0 {
		createVisualization(g, content, index, cfg)
	}

	return g.Wait()
}

func createBytes(slice []int, bitsPerByte int) []byte {
	var bytes []byte
	var tmp uint8
	var shift int

	for i, j := range slice {
		for k := 0; k < bitsPerByte; k++ {
			tmp |= (uint8(j) & (1 << uint8(7-shift%8)))
			shift = shift + 1
			if shift%8 == 0 && i != 0 {
				bytes = append(bytes, byte(tmp))
				tmp = 0
			}
		}
	}
	return bytes
}

func createPacket(ch chan []byte, packet []int, bpP int) error {
	var buf []byte
	var tmp int
	switch bpP {
	case 24:
		for _, i := range packet {
			buf = append(buf, byte(i))
		}
	case 3, 6, 9, 12, 15, 18, 21:
		var slice []int
		for i := 0; i < len(packet); i = i + 1 {
			if i%(bpP*8) == 0 && i != 0 {
				bytes := createBytes(slice, bpP/3)
				buf = append(buf, bytes...)
				slice = slice[:0]
			}
			slice = append(slice, packet[i])
		}
		bytes := createBytes(slice, bpP/3)
		buf = append(buf, bytes...)
	case 1:
		var j int
		for i := 0; i < len(packet); i = i + 3 {
			if j%8 == 0 && j != 0 {
				buf = append(buf, byte(tmp))
				tmp = 0
			}
			if packet[i] != 0 {
				tmp = tmp | (1 << uint8(7-j%8))
			}
			j = j + 1
		}
		if tmp != 0 {
			buf = append(buf, byte(tmp))
		}
	default:
		return fmt.Errorf("This format is not supported so far")
	}

	ch <- buf

	return nil
}

func extractInformation(g *errgroup.Group, ch chan []byte, cfg configs) error {
	inputfile, err := os.Open(cfg.file)
	if err != nil {
		return fmt.Errorf("Could not open file %s: %s\n", cfg.file, err.Error())
	}
	defer inputfile.Close()
	svg := bufio.NewScanner(inputfile)
	var limitX, limitY, bpP int
	var yLast int
	var packet []int
	defer close(ch)

	limits, err := regexp.Compile("^<svg width=\"(\\d+)\" height=\"(\\d+)\">$")
	if err != nil {
		return err
	}
	bpPconfig, err := regexp.Compile("\\s+BitsPerPixel=(\\d+)$")
	if err != nil {
		return err
	}
	pixel, err := regexp.Compile("^<rect x=\"(\\d+)\" y=\"(\\d+)\" width=\"\\d+\" height=\"\\d+\" style=\"fill:rgb\\((\\d+),(\\d+),(\\d+)\\)\" />$")
	if err != nil {
		return err
	}
	svgEnd, err := regexp.Compile("^</svg>$")
	if err != nil {
		return err
	}

	for svg.Scan() {
		switch {
		case limitX == 0 && limitY == 0:
			matches := limits.FindStringSubmatch(svg.Text())
			if len(matches) == 3 {
				limitX, _ = strconv.Atoi(matches[1])
				limitY, _ = strconv.Atoi(matches[2])
			}
		case bpP == 0:
			matches := bpPconfig.FindStringSubmatch(svg.Text())
			if len(matches) == 2 {
				bpP, _ = strconv.Atoi(matches[1])
			}
		default:
			matches := pixel.FindStringSubmatch(svg.Text())
			if len(matches) == 6 {
				pixelX, _ := strconv.Atoi(matches[1])
				pixelY, _ := strconv.Atoi(matches[2])
				if pixelY != yLast {
					yLast = pixelY
					if err := createPacket(ch, packet, bpP); err != nil {
						return err
					}
					packet = packet[:0]
				}
				if pixelX >= limitX {
					return fmt.Errorf("x-coordinate (%d) is bigger than the limit (%d)\n", pixelX, limitX)
				}
				r, _ := strconv.Atoi(matches[3])
				g, _ := strconv.Atoi(matches[4])
				b, _ := strconv.Atoi(matches[5])
				packet = append(packet, r, g, b)
			} else {
				end := svgEnd.FindStringSubmatch(svg.Text())
				if len(end) == 1 && len(packet) != 0 {
					return createPacket(ch, packet, bpP)
				}
			}
		}
	}
	return nil
}

func createPcap(g *errgroup.Group, ch chan []byte, cfg configs) error {
	filename := cfg.prefix
	filename += ".pcap"
	output, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("Could not create file %s: %s\n", filename, err.Error())
	}
	defer output.Close()
	w := pcapgo.NewWriter(output)
	w.WriteFileHeader(65536, layers.LinkTypeEthernet)

	for i, ok := <-ch; ok; i, ok = <-ch {
		w.WritePacket(gopacket.CaptureInfo{CaptureLength: len(i), Length: len(i), InterfaceIndex: 0}, i)
	}

	return nil
}

func reconstruct(g *errgroup.Group, cfg configs) error {
	ch := make(chan []byte)

	go extractInformation(g, ch, cfg)

	g.Go(func() error {
		return createPcap(g, ch, cfg)
	})

	return g.Wait()
}

func main() {
	var cfg configs
	g, ctx := errgroup.WithContext(context.Background())
	ctx, cancel := context.WithCancel(ctx)
	osSig := make(chan os.Signal)
	signal.Notify(osSig, os.Interrupt)
	defer func() {
		signal.Stop(osSig)
		cancel()
	}()

	go func() {
		select {
		case <-osSig:
			cancel()
		case <-ctx.Done():
			return
		}
	}()

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
	xlimit := flag.Uint("limit", 1500, "Maximim number of bytes per packet.\n\tIf your MTU is higher than the default value of 1500 you might change this value.")
	rebuild := flag.Bool("reverse", false, "Create a pcap from a svg")
	flag.Parse()

	if *lst {
		if err := availableInterfaces(); err != nil {
			fmt.Println("Could not list interfaces:", err)
		}
		return
	}

	if *vers {
		fmt.Println("Version:", Version)
		return
	}

	if *help {
		fmt.Println(os.Args[0], "[-list_interfaces] [-help] [-version]\n\t[-bits ...] [-count ...] [-limit ...] [-file ... |-interface ...] [-filter ...] [-prefix ...] [-scale ...] [-size ... | -timeslize ... |-terminal|-reverse]")
		flag.PrintDefaults()
		return
	}

	cfg.bpP = *bits
	cfg.ppI = *size
	cfg.ts = int64(*ts)
	cfg.limit = *num
	cfg.stil = 0
	cfg.scale = *scale
	cfg.xlimit = *xlimit
	cfg.dev = *dev
	cfg.file = *file
	cfg.filter = *filter
	cfg.prefix = *prefix

	if err := checkConfig(&cfg, *terminalOut, *rebuild); err != nil {
		fmt.Println("Configuration error:", err)
		return
	}

	if cfg.stil&reverse == cfg.stil {
		if err := reconstruct(g, cfg); err != nil {
			fmt.Println("Visualizon error:", err)
			return
		}
	} else {
		if err := visualize(g, cfg); err != nil {
			fmt.Println("Visualizon error:", err)
			return
		}
	}

}
