package main

import (
	"bufio"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"golang.org/x/sync/errgroup"
	"os"
	"regexp"
	"strconv"
)

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
