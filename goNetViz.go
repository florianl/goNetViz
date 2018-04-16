package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"golang.org/x/sync/errgroup"
)

const (
	solder     = 0x01
	terminal   = 0x02
	timeslize  = 0x04
	reverse    = 0x08
	stilMask   = 0x0f
	file       = 0x10
	dev        = 0x20
	usePcap    = 0x40
	sourceMask = 0x70
)

// Version number of this tool
const Version = "0.0.4"

// Data is a struct for each network packet
type data struct {
	toa     int64  // Timestamp of arrival in microseconds
	payload []byte // Copied network packet
}

// logicOp represents the logical operation
type logicOp struct {
	name  string                                    // logical operation name
	gate  func(payload []byte, operand byte) []byte // logical operation on the input bytes
	value byte                                      // value for the logical operation
}

// configs represents all the configuration data
type configs struct {
	bpP    uint   // Bits per Pixel
	ppI    uint   // Number of packets per Image
	ts     int64  // "Duration" for one Image
	limit  uint   // Number of network packets to process
	flags  uint   // Type of illustration
	scale  uint   // Scaling factor for output
	xlimit uint   // Limit of bytes per packet
	filter string // filter for the network interface
	input  string // source of data
	prefix string // prefix for the visualization results
	logicOp
}

type source interface {
	Read(uint) ([]byte, int64, error)
	Close() error
}

type regularFile struct {
	file *os.File
}

func (f regularFile) Read(limit uint) ([]byte, int64, error) {
	buf := make([]byte, int(limit))
	n, err := f.file.Read(buf)
	if n != int(limit) {
		return []byte{}, 0, fmt.Errorf("Could only read %d instead of %d bytes", n, limit)
	}
	if err != nil {
		return []byte{}, 0, err
	}

	return buf, 0, nil

}

func (f regularFile) Close() (err error) {
	f.file.Close()
	return err
}

type pcapInput struct {
	handle *pcap.Handle
	source *gopacket.PacketSource
}

func (p pcapInput) Read(limit uint) ([]byte, int64, error) {
	buf := make([]byte, int(limit))
	packet, err := p.source.NextPacket()
	if err != nil {
		return []byte{}, 0, err
	}
	toa := packet.Metadata().CaptureInfo.Timestamp.UnixNano() / int64(time.Microsecond)
	copy(buf, packet.Data())
	return buf, toa, nil
}

func (p pcapInput) Close() (err error) {
	p.handle.Close()
	return err
}

func getBitsFromPacket(packet []byte, byteP, bitP *int, bpP uint) uint8 {
	var c uint8
	for i := 0; i < (int(bpP) / 3); i++ {
		if *byteP >= len(packet) {
			break
		}
		c |= (packet[*byteP] & (1 << uint8(7-*bitP)))
		*bitP++
		if *bitP%8 == 0 {
			*bitP = 0
			*byteP++
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
		*bitP++
		if *bitP%8 == 0 {
			*bitP = 0
			*byteP++
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

func createImage(filename string, width, height int, content string, cfg configs) error {
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

	var source = cfg.input

	if _, err := f.WriteString(fmt.Sprintf("<!--\n\tgoNetViz \"%s\"\n\tScale=%d\n\tBitsPerPixel=%d\n\tDTG=\"%s\"\n\tSource=\"%s\"\n\tFilter=\"%s\"\n\tLogicGate=\"%s\"\n\tLogicValue=0x%X\n-->\n",
		Version, cfg.scale, cfg.bpP, time.Now().UTC(), source, cfg.filter, cfg.logicOp.name, cfg.logicOp.value)); err != nil {
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
	var yPos = -1
	var bitPos int
	var bytePos int
	var packetLen int
	var firstPkg time.Time
	var svg bytes.Buffer
	var bitsPerPixel = int(cfg.bpP)
	var scale = int(cfg.scale)
	var xLimit = cfg.xlimit
	var prefix = cfg.prefix
	var xMax int

	for pkg := range content {
		if firstPkg.IsZero() {
			firstPkg = time.Unix(0, content[pkg].toa*int64(time.Microsecond))
		}
		packetLen = len(content[pkg].payload)
		xPos = 0
		if (cfg.flags & stilMask) == solder {
			yPos++
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
	if (cfg.flags & stilMask) == timeslize {
		filename += firstPkg.Format(time.RFC3339Nano)
	} else {
		filename += fmt.Sprint(num)
	}
	filename += ".svg"

	g.Go(func() error {
		return createImage(filename, (xMax+1)*scale, (yPos+1)*scale, svg.String(), cfg)
	})
}

func handlePackets(g *errgroup.Group, input source, cfg configs, ch chan<- data) {
	var count uint
	var num = cfg.limit
	var limit = cfg.xlimit
	var logicValue = cfg.logicOp.value
	var logicGate = cfg.logicOp.gate

	defer close(ch)

	for {
		bytes, toa, err := input.Read(limit)
		if err != nil {

		}
		count++
		if num != 0 && count > num {
			break
		}

		if len(bytes) == 0 {
			continue
		}

		ch <- data{toa: toa, payload: logicGate(bytes, logicValue)}
	}
	return
}

func initPcapSource(input, filter string, device bool) (source, error) {
	var p pcapInput
	var err error

	if device {
		p.handle, err = pcap.OpenLive(input, 4096, true, -10*time.Microsecond)
		if err != nil {
			return nil, err
		}
	} else {
		p.handle, err = pcap.OpenOffline(input)
		if err != nil {
			return nil, err
		}
	}

	if len(filter) != 0 {
		err = p.handle.SetBPFFilter(filter)
		if err != nil {
			return nil, fmt.Errorf("%s\nInvalid Filter: %s", err, filter)
		}
	}

	p.source = gopacket.NewPacketSource(p.handle, layers.LayerTypeEthernet)
	p.source.DecodeOptions = gopacket.Lazy

	return p, nil
}

func initSource(input, filter string, pcap bool) (handle source, err error) {
	var device bool

	if _, err := net.InterfaceByName(input); err == nil {
		device = true
	}

	if len(filter) > 0 || pcap == true {
		return initPcapSource(input, filter, device)
	}

	if device {
		return nil, fmt.Errorf("Please open networking interface with pcap support")
	}

	fi, err := os.Lstat(input)
	if err != nil {
		return nil, fmt.Errorf("Could not get file information")
	}
	mode := fi.Mode()

	switch {
	case mode.IsRegular():
		f := new(regularFile)
		f.file, err = os.Open(input)
		handle = f
	case mode&os.ModeCharDevice == 0:
		f := new(regularFile)
		f.file, err = os.Open(input)
		handle = f
	case mode&os.ModeSocket == 0:
		f := new(regularFile)
		f.file, err = os.Open(input)
		handle = f
	default:
		return nil, fmt.Errorf(fmt.Sprintf("Can not handle %s as source", input))
	}
	return
}

func getOperand(val string) (byte, error) {
	var i int
	var j int64
	var err error

	smallVal := strings.ToLower(val)

	if strings.HasPrefix(smallVal, "0x") || strings.ContainsAny(smallVal, "abcdef") {
		j, err = strconv.ParseInt(strings.TrimPrefix(strings.ToLower(val), "0x"), 16, 16)
		i = int(j)
	} else {
		i, err = strconv.Atoi(val)
	}

	if err != nil {
		return 0x00, fmt.Errorf("Could not convert %s", val)
	}

	if i < 0 || i > 255 {
		return 0x0, fmt.Errorf("%s is not a valid value", val)
	}

	return byte(i), nil
}

func opXor(payload []byte, operand byte) []byte {
	for i := range payload {
		payload[i] ^= operand
	}
	return payload
}

func opOr(payload []byte, operand byte) []byte {
	for i := range payload {
		payload[i] |= operand
	}
	return payload
}

func opAnd(payload []byte, operand byte) []byte {
	for i := range payload {
		payload[i] &= operand
	}
	return payload
}

func opNot(payload []byte, operand byte) []byte {
	for i := range payload {
		payload[i] = ^(payload[i])
	}
	return payload
}

func opNand(payload []byte, operand byte) []byte {
	for i := range payload {
		payload[i] &^= operand
	}
	return payload
}

func opDefault(payload []byte, operand byte) []byte {
	return payload
}

func checkConfig(cfg *configs, console, rebuild bool, lGate string, lValue string) error {
	var err error

	switch strings.ToLower(lGate) {
	case "xor":
		cfg.logicOp.gate = opXor
		cfg.logicOp.name = "xor"
	case "or":
		cfg.logicOp.gate = opOr
		cfg.logicOp.name = "or"
	case "and":
		cfg.logicOp.gate = opAnd
		cfg.logicOp.name = "and"
	case "not":
		cfg.logicOp.gate = opNot
		cfg.logicOp.name = "not"
	case "nand":
		cfg.logicOp.gate = opNand
		cfg.logicOp.name = "nand"
	default:
		cfg.logicOp.gate = opDefault
		cfg.logicOp.name = "none"
	}

	cfg.logicOp.value, err = getOperand(lValue)
	if err != nil {
		return err
	}

	if console {
		cfg.flags |= terminal
	}

	if rebuild {
		cfg.flags |= reverse
	}

	if cfg.bpP%3 != 0 && cfg.bpP != 1 {
		return fmt.Errorf("-bits %d is not divisible by three or one", cfg.bpP)
	} else if cfg.bpP > 25 {
		return fmt.Errorf("-bits %d must be smaller than 25", cfg.bpP)
	}

	if cfg.ts > 0 {
		cfg.flags |= timeslize
	}

	switch stil := (cfg.flags & stilMask); stil {
	case (timeslize | terminal):
		return fmt.Errorf("-timeslize and -terminal can't be combined")
	case (timeslize | reverse):
		return fmt.Errorf("-timeslize and -reverse can't be combined")
	case (terminal | reverse):
		return fmt.Errorf("-terminal and -reverse can't be combined")
	case (terminal | timeslize | reverse):
		return fmt.Errorf("-terminal, -timeslize and -reverse can't be combined")
	case 0: /*	no specific option was given	*/
		cfg.flags |= solder
	}

	if (cfg.flags&stilMask) == reverse && (cfg.flags&sourceMask) != file {
		return fmt.Errorf("-file is needed as source")
	}

	if (cfg.flags&stilMask) == terminal && cfg.scale != 1 {
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
	var err error
	var handle source

	if (cfg.flags & sourceMask) == usePcap {
		handle, err = initSource(cfg.input, cfg.filter, true)
	} else {
		handle, err = initSource(cfg.input, cfg.filter, false)
	}
	if err != nil {
		return err
	}
	defer handle.Close()

	go handlePackets(g, handle, cfg, ch)

	switch stil := (cfg.flags & stilMask); stil {
	case solder:
		for i, ok := <-ch; ok; i, ok = <-ch {
			content = append(content, i)
			if len(content) >= int(cfg.ppI) && cfg.ppI != 0 {
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

func run(cfg configs) error {
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

	if (cfg.flags & stilMask) == reverse {
		if err := reconstruct(g, cfg); err != nil {
			return err
		}
	} else {
		if err := visualize(g, cfg); err != nil {
			return err
		}
	}
	return nil
}

func main() {
	var cfg configs

	input := flag.String("input", "", "Choose a source for further processing.")
	pcap := flag.Bool("pcap", false, "Try to open input with pcap.")
	filter := flag.String("filter", "", "Set a specific filter.")
	vers := flag.Bool("version", false, "Show version.")
	help := flag.Bool("help", false, "Show this help.")
	terminalOut := flag.Bool("terminal", false, "Visualize output on terminal.")
	num := flag.Uint("count", 25, "Number of packets to process.\n\tIf argument is 0 the limit is removed.")
	prefix := flag.String("prefix", "image", "Prefix of the resulting image.")
	size := flag.Uint("size", 25, "Number of packets per image.\n\tIf argument is 0 the limit is removed.")
	bits := flag.Uint("bits", 24, "Number of bits per pixel. It must be divisible by three and smaller than 25 or 1.\n\tTo get black/white results, choose 1 as input.")
	ts := flag.Uint("timeslize", 0, "Number of microseconds per resulting image.\n\tSo each pixel of the height of the resulting image represents one microsecond.")
	scale := flag.Uint("scale", 1, "Scaling factor for output.\n\tWorks not for output on terminal.")
	xlimit := flag.Uint("limit", 1500, "Maximim number of bytes per packet.\n\tIf your MTU is higher than the default value of 1500 you might change this value.")
	rebuild := flag.Bool("reverse", false, "Create a pcap from a svg")
	lGate := flag.String("logicGate", "", "Logical operation for the input")
	lValue := flag.String("logicValue", "0xFF", "Operand for the logical operation")

	flag.Parse()

	if *vers {
		fmt.Println("Version:", Version)
		return
	}

	if *help || len(os.Args) <= 1 {
		fmt.Println(os.Args[0], "[-list_interfaces] [-help] [-version]\n\t[-bits ...] [-count ...] [-limit ...] [-file ... |-interface ...] [-filter ...] [-prefix ...] [-scale ...] [-size ... | -timeslize ... |-terminal|-reverse]")
		flag.PrintDefaults()
		return
	}

	cfg.input = *input
	cfg.bpP = *bits
	cfg.ppI = *size
	cfg.ts = int64(*ts)
	cfg.limit = *num
	cfg.flags = 0
	cfg.scale = *scale
	cfg.xlimit = *xlimit
	cfg.filter = *filter
	cfg.prefix = *prefix

	if *pcap {
		cfg.flags |= usePcap
	}

	if err := checkConfig(&cfg, *terminalOut, *rebuild, *lGate, *lValue); err != nil {
		fmt.Println("Configuration error:", err)
		return
	}

	if err := run(cfg); err != nil {
		fmt.Println("goNetViz:", err)
		return
	}
}
