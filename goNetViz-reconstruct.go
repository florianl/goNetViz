package main

import (
	"bufio"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"golang.org/x/sync/errgroup"
	"os"
	"reflect"
	"regexp"
	"strconv"
)

// reconstructOptions represents all options for reconstruction
type reconstructOptions struct {
	BpP    int
	LimitX int
	LimitY int
	Scale  int
	Dtg    string
	Source string
	Filter string
}

// svgOptions represents various options for reconstruction
type svgOptions struct {
	regex             string
	reconstructOption string
}

func createPacket(ch chan<- []byte, packet []int, bpP int) error {
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

func checkVersion(parse *[]svgOptions, version string) (string, error) {

	scale := svgOptions{regex: "\\s+Scale=(\\d+)$", reconstructOption: "Scale"}
	*parse = append(*parse, scale)
	bpP := svgOptions{regex: "\\s+BitsPerPixel=(\\d+)$", reconstructOption: "BpP"}
	*parse = append(*parse, bpP)

	switch version {
	case "0.0.3":
		dtg := svgOptions{regex: "\\s+DTG=\"([0-9. :a-zA-Z]+)\"", reconstructOption: "Dtg"}
		*parse = append(*parse, dtg)
		source := svgOptions{regex: "\\s+Source=\"(\\w+)\"", reconstructOption: "Source"}
		*parse = append(*parse, source)
		filter := svgOptions{regex: "\\s+Filter=\"(\\w+)\"", reconstructOption: "Filter"}
		*parse = append(*parse, filter)
		fallthrough
	case "0.0.4":
	default:
		return "", fmt.Errorf("Unrecognized version: %s", version)
	}
	return version, nil
}

func checkHeader(svg *bufio.Scanner) (reconstructOptions, error) {
	var options reconstructOptions
	var variant string
	var header bool = false
	var parseOptions []svgOptions
	var optionIndex int

	limits, err := regexp.Compile("^<svg width=\"(\\d+)\" height=\"(\\d+)\">$")
	if err != nil {
		return options, err
	}
	headerStart, err := regexp.Compile("^<!--$")
	if err != nil {
		return options, err
	}
	headerEnd, err := regexp.Compile("^-->$")
	if err != nil {
		return options, err
	}
	version, err := regexp.Compile("\\s+goNetViz \"([0-9.]+)\"$")
	if err != nil {
		return options, err
	}

	for svg.Scan() {
		line := svg.Text()
		switch {
		case options.LimitX == 0 && options.LimitY == 0 && header == false:
			matches := limits.FindStringSubmatch(line)
			if len(matches) == 3 {
				options.LimitX, _ = strconv.Atoi(matches[1])
				options.LimitY, _ = strconv.Atoi(matches[2])
			}
		case header == false:
			if headerStart.MatchString(line) {
				header = true
			}
		case len(variant) == 0:
			matches := version.FindStringSubmatch(line)
			if len(matches) == 2 {
				variant, err = checkVersion(&parseOptions, matches[1])
				if err != nil {
					return options, fmt.Errorf("Unrecognized version: %s", matches[1])
				}
			}
		default:
			fmt.Println(parseOptions[optionIndex].reconstructOption)
			if optionIndex > len(parseOptions) {
				return options, fmt.Errorf("Option index is out of range")
			}
			regex, err := regexp.Compile(parseOptions[optionIndex].regex)
			if err != nil {
				return options, err
			}
			matches := regex.FindStringSubmatch(line)
			if len(matches) == 2 {
				option := reflect.ValueOf(&options).Elem().FieldByName(parseOptions[optionIndex].reconstructOption)

				switch option.Kind() {
				case reflect.Int:
					new, _ := strconv.Atoi(matches[1])
					option.SetInt(int64(new))
				case reflect.String:
					option.SetString(matches[1])
				default:
					return options, fmt.Errorf("Unhandeld option type")
				}
				optionIndex += 1
			} else {
				if headerEnd.MatchString(line) {
					return options, nil
				}
			}
		}
	}
	return options, fmt.Errorf("No end of header found")
}

func extractInformation(g *errgroup.Group, ch chan []byte, cfg configs) error {
	inputfile, err := os.Open(cfg.file)
	if err != nil {
		return fmt.Errorf("Could not open file %s: %s\n", cfg.file, err.Error())
	}
	defer inputfile.Close()
	svg := bufio.NewScanner(inputfile)
	var yLast int
	var packet []int
	defer close(ch)

	opt, err := checkHeader(svg)
	if err != nil {
		return err
	}

	pixel, err := regexp.Compile("^<rect x=\"(\\d+)\" y=\"(\\d+)\" width=\"\\d+\" height=\"\\d+\" style=\"fill:rgb\\((\\d+),(\\d+),(\\d+)\\)\" />$")
	if err != nil {
		return err
	}
	svgEnd, err := regexp.Compile("</svg>")
	if err != nil {
		return err
	}

	for svg.Scan() {
		line := svg.Text()
		matches := pixel.FindStringSubmatch(line)
		if len(matches) == 6 {
			pixelX, _ := strconv.Atoi(matches[1])
			pixelY, _ := strconv.Atoi(matches[2])
			if pixelY != yLast {
				yLast = pixelY
				if err := createPacket(ch, packet, opt.BpP); err != nil {
					return err
				}
				packet = packet[:0]
			}
			if pixelX >= opt.LimitX {
				return fmt.Errorf("x-coordinate (%d) is bigger than the limit (%d)\n", pixelX, opt.LimitX)
			}
			r, _ := strconv.Atoi(matches[3])
			g, _ := strconv.Atoi(matches[4])
			b, _ := strconv.Atoi(matches[5])
			packet = append(packet, r, g, b)
		} else if svgEnd.MatchString(line) {
			if len(packet) != 0 {
				return createPacket(ch, packet, opt.BpP)
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
