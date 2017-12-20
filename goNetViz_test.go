package main

import (
	"bytes"
	"context"
	"fmt"
	"golang.org/x/sync/errgroup"
	"io/ioutil"
	"os"
	"regexp"
	"testing"
)

var (
	notSvg         = `This is not a svg`
	withoutComment = `<?xml version="1.0"?>
<svg width="6" height="1">
<rect x="0" y="0" width="1" height="1" style="fill:rgb(0,0,0)" />
<rect x="1" y="0" width="1" height="1" style="fill:rgb(0,0,0)" />
<rect x="2" y="0" width="1" height="1" style="fill:rgb(0,0,0)" />
<rect x="3" y="0" width="1" height="1" style="fill:rgb(0,0,0)" />
<rect x="4" y="0" width="1" height="1" style="fill:rgb(0,0,0)" />
<rect x="5" y="0" width="1" height="1" style="fill:rgb(0,0,0)" />
</svg>`
	validSvg = `<?xml version="1.0"?>
<svg width="6" height="2">
<!--
	goNetViz "0.0.3"
	Scale=1
	BitsPerPixel=3
-->
<rect x="0" y="0" width="1" height="1" style="fill:rgb(0,0,0)" />
<rect x="1" y="0" width="1" height="1" style="fill:rgb(0,0,0)" />
<rect x="2" y="0" width="1" height="1" style="fill:rgb(0,0,0)" />
<rect x="0" y="1" width="1" height="1" style="fill:rgb(0,0,0)" />
<rect x="1" y="1" width="1" height="1" style="fill:rgb(0,0,0)" />
<rect x="2" y="1" width="1" height="1" style="fill:rgb(0,0,0)" />
</svg>`
	pcapHeader = []byte{
		0xa1, 0xb2, 0xc3, 0xd4, /*	Magic Number	*/
		0x00, 0x02, /*	Major Number	*/
		0x00, 0x04, /*	Minor Number	*/
		0x00, 0x00, 0x00, 0x00, /*	GMT to Local	*/
		0x00, 0x00, 0x00, 0x00, /*	Accuracy	*/
		0x00, 0x00, 0x00, 0x00, /*	Max captured Length	*/
		0x00, 0x00, 0x00, 0x01, /*	Data Link Type	*/
	}

	fakePacket = []byte{
		0x00, 0x00, 0x00, 0x00, /* Timestamp in seconds	*/
		0x00, 0x00, 0x00, 0x00, /* Timestamp in microseconds	*/
		0x00, 0x00, 0x00, 0x00, /* Number of Octets	*/
		0x00, 0x00, 0x00, 0x00, /* Actual Length	*/
	}
	fakeData = []byte{
		0xa1, 0xb2, 0xc3, 0xd4, 0x00, 0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x58, 0x30, 0x2d, 0x32, 0x00, 0x04, 0x63, 0x31,
		0x00, 0x00, 0x01, 0xeb, 0x00, 0x00, 0x01, 0xeb, 0x7a, 0xca, 0x8f, 0xfa, 0xfc, 0x34, 0x74, 0x73,
		0xa7, 0x4c, 0xe1, 0xef, 0x00, 0x45, 0x00, 0x08, 0xd8, 0x92, 0xdd, 0x01, 0x06, 0x40, 0x00, 0x40,
		0xa8, 0xc0, 0xfa, 0x24, 0xa8, 0xc0, 0xfd, 0xff, 0x33, 0x88, 0xf9, 0xff, 0x1f, 0xe9, 0x48, 0x1f,
		0x7a, 0x93, 0x41, 0x3f, 0x18, 0x80, 0x6d, 0xb7, 0xab, 0xac, 0x59, 0x05, 0x01, 0x01, 0x00, 0x00,
		0x37, 0x01, 0x0a, 0x08, 0x00, 0x00, 0xa3, 0xad, 0x45, 0x47, 0x2a, 0x2d, 0x73, 0x2f, 0x20, 0x54,
		0x70, 0x75, 0x74, 0x65, 0x72, 0x75, 0x65, 0x2f, 0x5f, 0x61, 0x6b, 0x65, 0x6f, 0x66, 0x6e, 0x69,
		0x72, 0x61, 0x70, 0x3f, 0x3d, 0x73, 0x6d, 0x61, 0x73, 0x72, 0x65, 0x76, 0x2c, 0x6e, 0x6f, 0x69,
		0x65, 0x6d, 0x61, 0x6e, 0x69, 0x75, 0x62, 0x2c, 0x69, 0x5f, 0x64, 0x6c, 0x2c, 0x6f, 0x66, 0x6e,
		0x69, 0x76, 0x65, 0x64, 0x69, 0x5f, 0x65, 0x63, 0x2c, 0x6f, 0x66, 0x6e, 0x2c, 0x74, 0x65, 0x6e,
		0x69, 0x66, 0x69, 0x77, 0x74, 0x65, 0x73, 0x2c, 0x73, 0x2c, 0x70, 0x75, 0x69, 0x74, 0x74, 0x65,
		0x2c, 0x73, 0x67, 0x6e, 0x5f, 0x74, 0x70, 0x6f, 0x6f, 0x2c, 0x6e, 0x69, 0x63, 0x6e, 0x65, 0x70,
		0x2c, 0x74, 0x73, 0x61, 0x74, 0x6c, 0x75, 0x6d, 0x6e, 0x6f, 0x7a, 0x69, 0x75, 0x61, 0x2c, 0x65,
		0x2c, 0x6f, 0x69, 0x64, 0x6e, 0x67, 0x69, 0x73, 0x74, 0x65, 0x64, 0x2c, 0x26, 0x6c, 0x69, 0x61,
		0x69, 0x74, 0x70, 0x6f, 0x3d, 0x73, 0x6e, 0x6f, 0x61, 0x74, 0x65, 0x64, 0x73, 0x2c, 0x6c, 0x69,
		0x20, 0x6e, 0x67, 0x69, 0x50, 0x54, 0x54, 0x48, 0x31, 0x2e, 0x31, 0x2f, 0x72, 0x4f, 0x0a, 0x0d,
		0x6e, 0x69, 0x67, 0x69, 0x74, 0x68, 0x20, 0x3a, 0x3a, 0x73, 0x70, 0x74, 0x77, 0x77, 0x2f, 0x2f,
		0x6f, 0x67, 0x2e, 0x77, 0x65, 0x6c, 0x67, 0x6f, 0x6d, 0x6f, 0x63, 0x2e, 0x63, 0x41, 0x0a, 0x0d,
		0x74, 0x70, 0x65, 0x63, 0x6e, 0x61, 0x4c, 0x2d, 0x67, 0x61, 0x75, 0x67, 0x65, 0x20, 0x3a, 0x65,
		0x53, 0x55, 0x2d, 0x6e, 0x6e, 0x65, 0x20, 0x2c, 0x30, 0x3d, 0x71, 0x3b, 0x20, 0x2c, 0x38, 0x2e,
		0x71, 0x3b, 0x6e, 0x65, 0x35, 0x2e, 0x30, 0x3d, 0x73, 0x55, 0x0a, 0x0d, 0x41, 0x2d, 0x72, 0x65,
		0x74, 0x6e, 0x65, 0x67, 0x6f, 0x63, 0x20, 0x3a, 0x6f, 0x67, 0x2e, 0x6d, 0x65, 0x6c, 0x67, 0x6f,
		0x64, 0x6e, 0x61, 0x2e, 0x64, 0x69, 0x6f, 0x72, 0x70, 0x70, 0x61, 0x2e, 0x68, 0x63, 0x2e, 0x73,
		0x65, 0x6d, 0x6f, 0x72, 0x74, 0x73, 0x61, 0x63, 0x70, 0x70, 0x61, 0x2e, 0x31, 0x2e, 0x31, 0x2f,
		0x39, 0x32, 0x2e, 0x39, 0x69, 0x4c, 0x28, 0x20, 0x3b, 0x78, 0x75, 0x6e, 0x20, 0x3b, 0x55, 0x20,
		0x72, 0x64, 0x6e, 0x41, 0x20, 0x64, 0x69, 0x6f, 0x2e, 0x30, 0x2e, 0x36, 0x4e, 0x20, 0x3b, 0x31,
		0x73, 0x75, 0x78, 0x65, 0x42, 0x20, 0x35, 0x20, 0x64, 0x6c, 0x69, 0x75, 0x42, 0x4f, 0x4d, 0x2f,
		0x29, 0x5a, 0x30, 0x33, 0x6f, 0x48, 0x0a, 0x0d, 0x20, 0x3a, 0x74, 0x73, 0x2e, 0x32, 0x39, 0x31,
		0x2e, 0x38, 0x36, 0x31, 0x2e, 0x35, 0x35, 0x32, 0x3a, 0x39, 0x34, 0x32, 0x38, 0x30, 0x30, 0x38,
		0x6f, 0x43, 0x0a, 0x0d, 0x63, 0x65, 0x6e, 0x6e, 0x6e, 0x6f, 0x69, 0x74, 0x65, 0x4b, 0x20, 0x3a,
		0x41, 0x2d, 0x70, 0x65, 0x65, 0x76, 0x69, 0x6c, 0x63, 0x41, 0x0a, 0x0d, 0x74, 0x70, 0x65, 0x63,
		0x63, 0x6e, 0x45, 0x2d, 0x6e, 0x69, 0x64, 0x6f, 0x67, 0x20, 0x3a, 0x67, 0x0d, 0x70, 0x69, 0x7a,
		0x00, 0x0a, 0x0d, 0x0a,
	}
)

func TestGetBitsFromPacket(t *testing.T) {

	var bytePos int
	var bitPos int
	tests := []struct {
		name   string
		packet []byte
		bpP    uint
		ret    uint8
	}{
		{"24 Bits", []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, 24, 255},
		{"21 Bits", []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, 21, 254},
		{"18 Bits", []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, 18, 252},
		{"15 Bits", []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, 15, 248},
		{"12 Bits", []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, 12, 240},
		{"9 Bits", []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, 9, 224},
		{"6 Bits", []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, 6, 192},
		{"3 Bits", []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, 3, 128},
		{"Too less bits", []byte{0x1}, 24, 1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Reset position, as the stream of provided bits is limited
			bytePos = 0
			bitPos = 0
			res := getBitsFromPacket(tc.packet, &bytePos, &bitPos, tc.bpP)
			if res != tc.ret {
				t.Errorf("Input: %d Expected: %d \t Got %d", tc.packet, tc.ret, res)
			}
		})
	}
}

func TestCheckConfig(t *testing.T) {
	tests := []struct {
		name    string
		cfg     configs
		console bool
		rebuild bool
		err     string
	}{
		// Testing different output stiles
		{name: "Two Bits per Pixel", cfg: configs{2, 0, 0, 0, terminal, 1, 1500, "dev", "filter", "file", "prefix"}, err: "-bits 2 is not divisible by three or one"},
		{name: "One Bit per Pixel", cfg: configs{1, 0, 0, 0, terminal, 1, 1500, "dev", "filter", "file", "prefix"}},
		{name: "27 Bits per Pixel", cfg: configs{27, 0, 0, 0, terminal, 1, 1500, "dev", "filter", "file", "prefix"}, err: "-bits 27 must be smaller than 25"},
		{name: "Terminal only", cfg: configs{3, 0, 0, 0, terminal, 1, 1500, "dev", "filter", "file", "prefix"}},
		{name: "Terminal and Timeslize", cfg: configs{3, 0, 0, 0, (terminal | timeslize), 1, 1500, "dev", "filter", "file", "prefix"}, console: true, err: "-timeslize and -terminal can't be combined"},
		{name: "Fixed Slize", cfg: configs{1, 0, 0, 0, 0, 1, 1500, "dev", "filter", "file", "prefix"}},
		{name: "Time Slize", cfg: configs{1, 0, 50, 0, 0, 1, 1500, "dev", "filter", "file", "prefix"}},
		{name: "Scale and Terminal", cfg: configs{1, 0, 0, 0, terminal, 2, 1500, "dev", "filter", "file", "prefix"}, console: true, err: "-scale and -terminal can't be combined"},
		{name: "Time Slize", cfg: configs{1, 0, 50, 0, 0, 0, 1500, "dev", "filter", "file", "prefix"}, err: "scale factor has to be at least 1"},
		{name: "Time Slize, Terminal and Rebuild", cfg: configs{1, 0, 50, 0, 0, 0, 1500, "dev", "filter", "file", "prefix"}, console: true, rebuild: true, err: "-terminal, -timeslize and -reverse can't be combined"},
		{name: "Time Slize and Rebuild", cfg: configs{1, 0, 50, 0, 0, 0, 1500, "dev", "filter", "file", "prefix"}, rebuild: true, err: "-timeslize and -reverse can't be combined"},
		{name: "Terminal and Rebuild", cfg: configs{1, 0, 0, 0, 0, 1, 1500, "dev", "filter", "file", "prefix"}, console: true, rebuild: true, err: "-terminal and -reverse can't be combined"},
		{name: "Rebuild without file", cfg: configs{1, 0, 0, 0, 0, 1, 1500, "dev", "filter", "", "prefix"}, console: false, rebuild: true, err: "-file is needed as source"},
		{name: "Jumbo frame", cfg: configs{1, 0, 0, 0, 0, 1, 15000, "dev", "filter", "file", "prefix"}, err: "limit has to be smallerthan a Jumbo frame (9000 bytes)"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := checkConfig(&tc.cfg, tc.console, tc.rebuild)

			if tc.err != "" {
				if res.Error() != tc.err {
					t.Errorf("Expected: %v \t Got: %v", tc.err, res)
				}
			}
		})
	}
}

func TestCreatePixel(t *testing.T) {
	tests := []struct {
		name   string
		packet []byte
		byteP  int
		bitP   int
		bpP    uint
		red    uint8
		green  uint8
		blue   uint8
	}{
		{"White", []byte{0xFF, 0xFF}, 0, 0, 1, 255, 255, 255},
		{"Black", []byte{0x00, 0x00}, 0, 0, 1, 0, 0, 0},
		{"Royal Blue", []byte{0x41, 0x69, 0xE1, 0x41, 0x69, 0xE1}, 0, 0, 24, 65, 105, 225},
		{"Byte Boundary", []byte{0xA5, 0xA5, 0xA5}, 0, 6, 24, 165, 165, 1},
		{"Byte Boundary", []byte{0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A}, 0, 7, 1, 0, 0, 0},
		{"Too less bits", []byte{0xFF}, 0, 0, 24, 255, 0, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, g, b := createPixel(tc.packet, &(tc.byteP), &(tc.bitP), tc.bpP)
			if uint8(r) != tc.red || uint8(g) != tc.green || uint8(b) != tc.blue {
				t.Errorf("Expected: r%dg%db%d\t Got: r%dg%db%d", tc.red, tc.green, tc.blue, uint8(r), uint8(g), uint8(b))
			}
		})
	}
}

func TestInitSource(t *testing.T) {

	tdir, ferr := ioutil.TempDir("", "initSource")
	if ferr != nil {
		t.Fatal(ferr)
	}
	defer os.RemoveAll(tdir)
	fakePcap, ferr := ioutil.TempFile(tdir, "fake.pcap")
	if ferr != nil {
		t.Fatal(ferr)
	}
	defer os.Remove(fakePcap.Name())

	ferr = ioutil.WriteFile(fakePcap.Name(), fakeData, 0644)
	if ferr != nil {
		t.Fatal(ferr)
	}
	defer fakePcap.Close()

	emptyPcap, ferr := ioutil.TempFile(tdir, "empty.pcap")
	if ferr != nil {
		t.Fatal(ferr)
	}
	defer os.Remove(emptyPcap.Name())
	ferr = ioutil.WriteFile(emptyPcap.Name(), pcapHeader, 0644)
	if ferr != nil {
		t.Fatal(ferr)
	}
	ferr = ioutil.WriteFile(emptyPcap.Name(), fakePacket, 0644)
	if ferr != nil {
		t.Fatal(ferr)
	}
	defer emptyPcap.Close()

	tests := []struct {
		name   string
		dev    string
		file   string
		filter string
		err    string
	}{
		{name: "No Source", dev: "", file: "", err: "Source is missing"},
		{name: "Invalid File", dev: "", file: "/invalid/file", err: "No such file or directory"},
		{name: "Non existing Device", dev: "/dev/InvalidDevice", file: "", err: "(No such device exists)|(Operation not permitted)"},
		{name: "Invalid Filter", file: fmt.Sprintf("%s", fakePcap.Name()), filter: "noFilter", err: "syntax error"},
		{name: "Unknown file format", file: fmt.Sprintf("%s", emptyPcap.Name()), err: "unknown file format"},
		{name: "No Errors", file: fmt.Sprintf("%s", fakePcap.Name())},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := initSource(tc.dev, tc.file, tc.filter)
			if err != nil {
				if matched, _ := regexp.MatchString(tc.err, err.Error()); matched == false {
					t.Errorf("Error matching regex: %v \t Got: %v", tc.err, err)
				}
			} else if len(tc.err) != 0 {
				t.Fatalf("Expected error, got none")
			}
		})
	}

}

func TestCreateImage(t *testing.T) {

	dir, err := ioutil.TempDir("", "TestCreateImage")
	if err != nil {
		t.Errorf("Could not create temporary directory: %v", err)
	}

	defer os.RemoveAll(dir)
	tests := []struct {
		name     string
		filename string
		width    int
		height   int
		data     string
	}{
		{name: "No Filename", filename: "", data: "<rect x=\"0\" y=\"0\" width=\"1\" height=\"1\" style=\"fill:rgb(0,0,0)\" />"},
		{name: "Just directory name", filename: dir, data: "<rect x=\"0\" y=\"0\" width=\"1\" height=\"1\" style=\"fill:rgb(0,0,0)\" />"},
		{name: "No Data", filename: fmt.Sprintf("%s/test.svg", dir)},
		{name: "Without errors", filename: fmt.Sprintf("%s/test.svg", dir), data: "<rect x=\"0\" y=\"0\" width=\"1\" height=\"1\" style=\"fill:rgb(0,0,0)\" />"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			createImage(tc.filename, tc.width, tc.height, tc.data, 1, 1)
		})
	}
}

func TestCreateVisualization(t *testing.T) {
	dir, err := ioutil.TempDir("", "TestCreateVisualization")
	if err != nil {
		t.Errorf("Could not create temporary directory: %v", err)
	}
	defer os.RemoveAll(dir)

	tests := []struct {
		name    string
		content []data
		xLimit  uint
		prefix  string
		num     uint
		cfg     configs
		err     string
	}{
		{name: "No Data", xLimit: 1, prefix: fmt.Sprintf("%s/noData", dir), num: 1, cfg: configs{1, 0, 0, 0, solder, 1, 1500, "dev", "filter", "file", "prefix"}, err: "No image data provided"},
		{name: "Solid image", content: []data{{toa: 0, payload: []byte{0xCA, 0xFE, 0xBA, 0xBE}}}, xLimit: 1, prefix: fmt.Sprintf("%s/solid", dir), num: 1, cfg: configs{24, 0, 0, 0, solder, 1, 1500, "dev", "filter", "file", "prefix"}},
		{name: "Timeslize image", content: []data{{toa: 0, payload: []byte{0xCA, 0xFE, 0xBA, 0xBE}}}, xLimit: 1, prefix: fmt.Sprintf("%s/timeslize", dir), num: 1, cfg: configs{24, 0, 0, 0, timeslize, 1, 1500, "dev", "filter", "file", "prefix"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g, _ := errgroup.WithContext(context.Background())
			createVisualization(g, tc.content, tc.num, tc.cfg)
		})
	}
}

func TestCreateTerminalVisualization(t *testing.T) {
	tests := []struct {
		name string
		pkt1 data
		pkt2 data
		cfg  configs
	}{
		{name: "bytePos >= pkt1Len", pkt1: data{toa: 0, payload: []byte{0x01}}, pkt2: data{toa: 0, payload: []byte{0xCA, 0xFE, 0xC0, 0x00, 0x10, 0xFF, 0xC0, 0xFF, 0xEE}}, cfg: configs{3, 0, 0, 0, timeslize, 1, 1500, "dev", "filter", "file", "prefix"}},
		{name: "bytePos >= pkt2Len", pkt1: data{toa: 0, payload: []byte{0xCA, 0xFE, 0xC0, 0x00, 0x10, 0xFF, 0xC0, 0xFF, 0xEE}}, pkt2: data{toa: 0, payload: []byte{0x01}}, cfg: configs{3, 0, 0, 0, timeslize, 1, 1500, "dev", "filter", "file", "prefix"}},
		{name: "pkt1Len == pkt2Len", pkt1: data{toa: 0, payload: []byte{0xCA, 0xFE, 0xC0, 0x00, 0x10, 0xFF, 0xC0, 0xFF, 0xEE}}, pkt2: data{toa: 0, payload: []byte{0xCA, 0xFE, 0xC0, 0x00, 0x10, 0xFF, 0xC0, 0xFF, 0xEE}}, cfg: configs{3, 0, 0, 0, timeslize, 1, 1500, "dev", "filter", "file", "prefix"}},
		{name: "pkt1Len == 0", pkt1: data{toa: 0, payload: []byte{}}, pkt2: data{toa: 0, payload: []byte{0xCA, 0xFE, 0xC0, 0x00, 0x10, 0xFF, 0xC0, 0xFF, 0xEE}}, cfg: configs{3, 0, 0, 0, timeslize, 1, 1500, "dev", "filter", "file", "prefix"}},
		{name: "pkt2Len == 0", pkt1: data{toa: 0, payload: []byte{0xCA, 0xFE, 0xC0, 0x00, 0x10, 0xFF, 0xC0, 0xFF, 0xEE}}, pkt2: data{toa: 0, payload: []byte{}}, cfg: configs{3, 0, 0, 0, timeslize, 1, 1500, "dev", "filter", "file", "prefix"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			createTerminalVisualization(tc.pkt1, tc.pkt2, tc.cfg)
		})
	}
}

func TestCreateBytes(t *testing.T) {
	tests := []struct {
		name        string
		slice       []int
		bitsPerByte int
		ret         []byte
	}{
		{name: "2 Bit", slice: []int{5, 10, 204, 51, 5, 10, 204, 51}, bitsPerByte: 1, ret: []byte{0x11}},
		{name: "3 Bits", slice: []int{5, 10, 204, 51, 5, 10, 204, 51}, bitsPerByte: 1, ret: []byte{0x11}},
		{name: "4 Bits", slice: []int{5, 10, 204, 51, 5, 10, 204, 51}, bitsPerByte: 1, ret: []byte{0x11}},
		{name: "5 Bits", slice: []int{5, 10, 204, 51, 5, 10, 204, 51}, bitsPerByte: 1, ret: []byte{0x11}},
		{name: "6 Bits", slice: []int{5, 10, 204, 51, 5, 10, 204, 51}, bitsPerByte: 1, ret: []byte{0x11}},
		{name: "7 Bits", slice: []int{5, 10, 204, 51, 5, 10, 204, 51}, bitsPerByte: 1, ret: []byte{0x11}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ret := createBytes(tc.slice, tc.bitsPerByte)
			if bytes.Compare(ret, tc.ret) != 0 {
				t.Errorf("Expected: %v \t Got: %v", tc.ret, ret)
			}
		})
	}
}

func TestCreatePcap(t *testing.T) {
	dir, err := ioutil.TempDir("", "TestCreatePcap")
	if err != nil {
		t.Errorf("Could not create temporary directory: %v", err)
	}
	defer os.RemoveAll(dir)
	tests := []struct {
		name    string
		payload []byte
		cfg     configs
		err     string
	}{
		{name: "Simple", cfg: configs{1, 0, 0, 0, 0, 1, 1500, "", "", "", fmt.Sprintf("%s/simple", dir)}, payload: []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g, _ := errgroup.WithContext(context.Background())
			ch := make(chan []byte)
			go func() {
				ch <- tc.payload
				close(ch)
			}()
			err := createPcap(g, ch, tc.cfg)
			if err != nil {
				if matched, _ := regexp.MatchString(tc.err, err.Error()); matched == false {
					t.Errorf("Error matching regex: %v \t Got: %v", tc.err, err)
				}
			} else if len(tc.err) != 0 {
				t.Fatalf("Expected error, got none")
			}
		})
	}
}

func TestCreatePacket(t *testing.T) {
	dir, err := ioutil.TempDir("", "TestCreatePcap")
	if err != nil {
		t.Errorf("Could not create temporary directory: %v", err)
	}
	defer os.RemoveAll(dir)
	tests := []struct {
		name   string
		recv   []byte
		packet []int
		bpP    int
		err    string
	}{
		{name: "24 BitsPerPixel", recv: []byte{8, 16, 32, 64, 128}, packet: []int{8, 16, 32, 64, 128}, bpP: 24},
		{name: "12 BitPerPixel", recv: []byte{1, 2, 5, 13, 18, 57, 153}, packet: []int{0, 1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233}, bpP: 12},
		{name: "3 BitPerPixel", recv: []byte{5, 49, 14}, packet: []int{0, 1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233, 144, 89, 55, 34, 21, 13, 8, 5, 3, 2, 1, 1, 0}, bpP: 3},
		{name: "2 BitsPerPixel", recv: []byte{8, 16, 32, 64, 128}, packet: []int{8, 16, 32, 64, 128}, bpP: 2, err: "This format is not supported so far"},
		{name: "1 BitPerPixel", recv: []byte{1, 8}, packet: []int{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0}, bpP: 1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ch := make(chan []byte)
			var recv []byte
			go func() {
				for i, ok := <-ch; ok; i, ok = <-ch {
					recv = append(recv, i...)
				}
				close(ch)
			}()
			err := createPacket(ch, tc.packet, tc.bpP)
			if err != nil {
				if matched, _ := regexp.MatchString(tc.err, err.Error()); matched == false {
					t.Errorf("Error matching regex: %v \t Got: %v", tc.err, err)
				}
			} else if len(tc.err) != 0 {
				t.Fatalf("Expected error, got none")
			} else if bytes.Compare(recv, tc.recv) != 0 {
				t.Errorf("Expected: %v \t Got: %v", tc.recv, recv)
			}
		})
	}
}

func TestExtractInformation(t *testing.T) {
	dir, err := ioutil.TempDir("", "TestExtractInformation")
	if err != nil {
		t.Errorf("Could not create temporary directory: %v", err)
	}
	defer os.RemoveAll(dir)

	notSvgFile, err := ioutil.TempFile("", "notSvg.svg")
	if err != nil {
		t.Errorf("Could not create temporary file: %v", err)
	}

	defer os.Remove(notSvgFile.Name())

	if _, err := notSvgFile.WriteString(notSvg); err != nil {
		t.Errorf("Could not write in temporary file: %v", err)
	}
	if err := notSvgFile.Close(); err != nil {
		t.Errorf("Could not close temporary file: %v", err)
	}

	withoutCommentFile, err := ioutil.TempFile("", "withoutComment.svg")
	if err != nil {
		t.Errorf("Could not create temporary file: %v", err)
	}

	defer os.Remove(withoutCommentFile.Name())

	if _, err := withoutCommentFile.WriteString(withoutComment); err != nil {
		t.Errorf("Could not write in temporary file: %v", err)
	}
	if err := withoutCommentFile.Close(); err != nil {
		t.Errorf("Could not close temporary file: %v", err)
	}

	validSvgFile, err := ioutil.TempFile("", "validSvg.svg")
	if err != nil {
		t.Errorf("Could not create temporary file: %v", err)
	}
	defer os.Remove(validSvgFile.Name())

	if _, err := validSvgFile.WriteString(validSvg); err != nil {
		t.Errorf("Could not write in temporary file: %v", err)
	}
	if err := validSvgFile.Close(); err != nil {
		t.Errorf("Could not close temporary file: %v", err)
	}

	tests := []struct {
		name string
		cfg  configs
		recv []byte
		err  string
	}{
		{name: "No file", cfg: configs{1, 0, 0, 0, 0, 1, 1500, "", "", "noFile", ""}, err: "Could not open file"},
		{name: "Not a svg", cfg: configs{1, 0, 0, 0, 0, 1, 1500, "", "", fmt.Sprintf("%s", notSvgFile.Name()), fmt.Sprintf("%s/not_a_svg", dir)}},
		{name: "Without Comment", cfg: configs{1, 0, 0, 0, 0, 1, 1500, "", "", fmt.Sprintf("%s", withoutCommentFile.Name()), fmt.Sprintf("%s/without_comment", dir)}},
		{name: "Valid svg", cfg: configs{1, 0, 0, 0, 0, 1, 1500, "", "", fmt.Sprintf("%s", validSvgFile.Name()), fmt.Sprintf("%s/valid_svg", dir)}, recv: []byte{0, 0}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g, _ := errgroup.WithContext(context.Background())
			ch := make(chan []byte)
			var recv []byte
			go func() {
				for i, ok := <-ch; ok; i, ok = <-ch {
					recv = append(recv, i...)
				}
			}()
			err := extractInformation(g, ch, tc.cfg)
			if err != nil {
				if matched, _ := regexp.MatchString(tc.err, err.Error()); matched == false {
					t.Errorf("Error matching regex: %v \t Got: %v", tc.err, err)
				}
			} else if len(tc.err) != 0 {
				t.Fatalf("Expected error, got none")
			} else if bytes.Compare(recv, tc.recv) != 0 {
				t.Errorf("Expected: %v \t Got: %v", tc.recv, recv)
			}
		})
	}
}

func TestVisualize(t *testing.T) {
	tdir, ferr := ioutil.TempDir("", "visualize")
	if ferr != nil {
		t.Fatal(ferr)
	}
	defer os.RemoveAll(tdir)
	fakePcap, ferr := ioutil.TempFile(tdir, "fake.pcap")
	if ferr != nil {
		t.Fatal(ferr)
	}
	defer os.Remove(fakePcap.Name())

	ferr = ioutil.WriteFile(fakePcap.Name(), fakeData, 0644)
	if ferr != nil {
		t.Fatal(ferr)
	}
	defer fakePcap.Close()

	tests := []struct {
		name string
		cfg  configs
		err  string
	}{
		{name: "solder", cfg: configs{1, 2, 0, 0, solder, 1, 1500, "", "", fmt.Sprintf("%s", fakePcap.Name()), ""}},
		{name: "terminal", cfg: configs{24, 0, 0, 0, terminal, 1, 1500, "", "", fmt.Sprintf("%s", fakePcap.Name()), ""}},
		{name: "timeslize", cfg: configs{1, 2, 0, 0, timeslize, 1, 1500, "", "", fmt.Sprintf("%s", fakePcap.Name()), ""}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g, _ := errgroup.WithContext(context.Background())
			err := visualize(g, tc.cfg)
			if err != nil {
				if matched, _ := regexp.MatchString(tc.err, err.Error()); matched == false {
					t.Errorf("Error matching regex: %v \t Got: %v", tc.err, err)
				}
			} else if len(tc.err) != 0 {
				t.Fatalf("Expected error, got none")
			}
		})
	}
}
