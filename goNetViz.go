package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"os"
	"os/signal"
	"time"
)

const (
	solder    = 0x01
	terminal  = 0x02
	timeslize = 0x04
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
	bpP    uint // Bits per Pixel
	ppI    uint // Number of packets per Image
	ts     uint // "Duration" for one Image
	limit  uint // Number of network packets to process
	stil   uint // Type of illustration
	scale  uint // Scaling factor for output
	xlimit uint // Limit of bytes per packet
}

type ctrlCtx struct {
	ctx    context.Context
	cancel context.CancelFunc
	err    error
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

func createImage(ctrl ctrlCtx, filename string, width, height int, content string, scale int, bitsPerPixel int) {
	if len(content) == 0 {
		ctrl.err = fmt.Errorf("No image data provided")
		ctrl.cancel()
		return
	}

	f, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		ctrl.err = err
		ctrl.cancel()
		return
	}

	if _, err := f.WriteString(fmt.Sprintf("<?xml version=\"1.0\"?>\n<svg width=\"%d\" height=\"%d\">\n", width, height)); err != nil {
		f.Close()
		ctrl.err = err
		ctrl.cancel()
		return
	}

	if _, err := f.WriteString(fmt.Sprintf("<!--\n\tgoNetViz \"%s\"\n\tScale=%d\n\tBitsPerPixel=%d\n-->\n",
		Version, scale, bitsPerPixel)); err != nil {
		f.Close()
		ctrl.err = err
		ctrl.cancel()
		return
	}

	if _, err := f.WriteString(content); err != nil {
		f.Close()
		ctrl.err = err
		ctrl.cancel()
		return
	}

	if _, err := f.WriteString("</svg>"); err != nil {
		f.Close()
		ctrl.err = err
		ctrl.cancel()
		return
	}

	if err := f.Close(); err != nil {
		ctrl.err = err
		ctrl.cancel()
		return
	}
}

func createVisualization(ctrl ctrlCtx, content []data, xLimit uint, prefix string, num uint, cfg configs) {
	var xPos int
	var yPos int = -1
	var bitPos int
	var bytePos int
	var packetLen int
	var firstPkg time.Time
	var svg bytes.Buffer
	var bitsPerPixel int = int(cfg.bpP)
	var scale int = int(cfg.scale)
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

	createImage(ctrl, filename, (xMax+1)*scale, (yPos+1)*scale, svg.String(), scale, bitsPerPixel)
}

func handlePackets(ctrl ctrlCtx, ps *gopacket.PacketSource, num uint, ch chan<- data) {
	var count uint
	for packet := range ps.Packets() {
		select {
		case <-ctrl.ctx.Done():
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

func initSource(dev, file *string, filter *string) (handle *pcap.Handle, err error) {
	if len(*dev) > 0 {
		handle, err = pcap.OpenLive(*dev, 4096, true, -10*time.Microsecond)
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

func checkConfig(cfg *configs, console bool) error {

	if console {
		cfg.stil |= terminal
	}

	if cfg.bpP%3 != 0 && cfg.bpP != 1 {
		return fmt.Errorf("-bits %d is not divisible by three or one", cfg.bpP)
	} else if cfg.bpP > 25 {
		return fmt.Errorf("-bits %d must be smaller than 25", cfg.bpP)
	}

	if cfg.ts > 0 {
		cfg.stil |= timeslize
	}

	if cfg.stil == (timeslize | terminal) {
		return fmt.Errorf("-timeslize and -terminal can't be combined")
	} else if cfg.stil == 0 {
		cfg.stil |= solder
	}

	if cfg.stil == terminal && cfg.scale != 1 {
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
	var content []data
	var index uint = 1
	var slicer int64
	var cfg configs
	ch := make(chan data)
	ctx, cancel := context.WithCancel(context.Background())
	ctrl := ctrlCtx{
		ctx:    ctx,
		cancel: cancel,
		err:    nil,
	}
	osSig := make(chan os.Signal)
	signal.Notify(osSig, os.Interrupt)
	defer func() {
		signal.Stop(osSig)
		ctrl.cancel()
	}()

	go func() {
		select {
		case <-osSig:
			ctrl.cancel()
		case <-ctrl.ctx.Done():
			if ctrl.err != nil {
				fmt.Println(ctrl.err.Error())
			}
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

	if *help {
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
	cfg.xlimit = *xlimit

	if err = checkConfig(&cfg, *terminalOut); err != nil {
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

	go handlePackets(ctrl, packetSource, cfg.limit, ch)

	switch cfg.stil {
	case solder:
		for i, ok := <-ch; ok; i, ok = <-ch {
			content = append(content, i)
			if len(content) >= int(cfg.ppI) {
				createVisualization(ctrl, content, *xlimit, *prefix, index, cfg)
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
				slicer = i.toa + int64(*ts)
			}
			if slicer < i.toa {
				createVisualization(ctrl, content, *xlimit, *prefix, 0, cfg)
				content = content[:0]
				slicer = i.toa + int64(*ts)
			}
			content = append(content, i)
		}
	}

	if len(content) > 0 {
		createVisualization(ctrl, content, *xlimit, *prefix, index, cfg)
	}

}
