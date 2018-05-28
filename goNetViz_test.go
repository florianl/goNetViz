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
	validSvg003 = `<?xml version="1.0"?>
<svg width="6" height="2">
<!--
	goNetViz "0.0.3"
	Scale=1
	BitsPerPixel=3
	DTG="Thu Nov 09 18:57:00 CET 1989"
-->
<rect x="0" y="0" width="1" height="1" style="fill:rgb(0,0,0)" />
<rect x="1" y="0" width="1" height="1" style="fill:rgb(0,0,0)" />
<rect x="2" y="0" width="1" height="1" style="fill:rgb(0,0,0)" />
<rect x="0" y="1" width="1" height="1" style="fill:rgb(0,0,0)" />
<rect x="1" y="1" width="1" height="1" style="fill:rgb(0,0,0)" />
<rect x="2" y="1" width="1" height="1" style="fill:rgb(0,0,0)" />
</svg>`
	validSvg004 = `<?xml version="1.0"?>
<svg width="6" height="4">
<!--
	goNetViz "0.0.4"
	Scale=1
	BitsPerPixel=24
	DTG="Wed Sep 07 16:05:00 CET 1949"
	Source="Bonn/Germany"
	Filter="none"
	LogicGate="none"
	LogicValue=0xFF

-->
<rect x="0" y="0" width="1" height="1" style="fill:rgb(255,0,0)" />
<rect x="1" y="0" width="1" height="1" style="fill:rgb(0,255,0)" />
<rect x="2" y="0" width="1" height="1" style="fill:rgb(0,0,255)" />
<rect x="0" y="1" width="1" height="1" style="fill:rgb(0,255,0)" />
<rect x="1" y="1" width="1" height="1" style="fill:rgb(255,0,0)" />
<rect x="2" y="1" width="1" height="1" style="fill:rgb(0,255,0)" />
<rect x="0" y="2" width="1" height="1" style="fill:rgb(0,0,255)" />
<rect x="1" y="2" width="1" height="1" style="fill:rgb(0,255,0)" />
<rect x="2" y="2" width="1" height="1" style="fill:rgb(255,0,0)" />
<rect x="0" y="3" width="1" height="1" style="fill:rgb(0,255,0)" />
<rect x="1" y="3" width="1" height="1" style="fill:rgb(0,0,255)" />
<rect x="2" y="3" width="1" height="1" style="fill:rgb(0,255,0)" />
</svg>`
	invalidVersion = `<?xml version="1.0"?>
<svg width="6" height="2">
<!--
	goNetViz "0.0.0"
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
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2f, 0x00, 0x00, 0x00, 0x2f, 0x00,
		0xc0, 0x25, 0x06, 0x44, 0xfc, 0x43, 0x5c, 0xe0, 0xc5, 0x8a, 0xa1, 0x79, 0x08, 0x00, 0x45, 0x00,
		0x00, 0x21, 0x00, 0x01, 0x00, 0x00, 0x40, 0x01, 0xf7, 0xf5, 0xc0, 0xa8, 0xb2, 0x2d, 0x08, 0x08,
		0x08, 0x08, 0x08, 0x00, 0x6d, 0x69, 0x00, 0x00, 0x00, 0x00, 0x23, 0x33, 0x34, 0x63, 0x33,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2f, 0x00, 0x00, 0x00, 0x2f, 0x00,
		0xc0, 0x25, 0x06, 0x44, 0xfc, 0x43, 0x5c, 0xe0, 0xc5, 0x8a, 0xa1, 0x79, 0x08, 0x00, 0x45, 0x01,
		0x00, 0x21, 0x00, 0x01, 0x00, 0x00, 0x40, 0x01, 0xf7, 0xf5, 0xc0, 0xa8, 0xb2, 0x2d, 0x08, 0x08,
		0x08, 0x08, 0x08, 0x00, 0x98, 0x28, 0x00, 0x00, 0x00, 0x00, 0x74, 0x75, 0x77, 0x61, 0x74,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2f, 0x00, 0x00, 0x00, 0x2f, 0x00,
		0xc0, 0x25, 0x06, 0x44, 0xfc, 0x43, 0x5c, 0xe0, 0xc5, 0x8a, 0xa1, 0x79, 0x08, 0x00, 0x45, 0x00,
		0x00, 0x21, 0x00, 0x01, 0x00, 0x00, 0x40, 0x01, 0xf7, 0xf5, 0xc0, 0xa8, 0xb2, 0x2d, 0x08, 0x08,
		0x08, 0x08, 0x08, 0x00, 0x6d, 0x69, 0x00, 0x00, 0x00, 0x00, 0x23, 0x33, 0x34, 0x63, 0x33,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2f, 0x00, 0x00, 0x00, 0x2f, 0x00,
		0xc0, 0x25, 0x06, 0x44, 0xfc, 0x43, 0x5c, 0xe0, 0xc5, 0x8a, 0xa1, 0x79, 0x08, 0x00, 0x45, 0x00,
		0x00, 0x21, 0x00, 0x01, 0x00, 0x00, 0x40, 0x01, 0xf7, 0xf5, 0xc0, 0xa8, 0xb2, 0x2d, 0x08, 0x08,
		0x08, 0x08, 0x08, 0x00, 0x6d, 0x69, 0x00, 0x00, 0x00, 0x00, 0x23, 0x33, 0x34, 0x63, 0x33,
	}
)

func TestGetBitsFromPacket(t *testing.T) {
	t.Parallel()

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
				t.Fatalf("Input: %d Expected: %d \t Got %d", tc.packet, tc.ret, res)
			}
		})
	}
}

func TestCheckConfig(t *testing.T) {

	logic := logicOp{
		name:  "none",
		gate:  nil,
		value: 0,
	}

	tests := []struct {
		name    string
		cfg     configs
		console bool
		rebuild bool
		lGate   string
		lValue  string
		err     string
	}{
		// Testing different output stiles
		{name: "Two Bits per Pixel", cfg: configs{2, 0, 0, 0, terminal, 1, 1500, "filter", "input", "prefix", logic}, lGate: "xor", lValue: "255", err: "-bits 2 is not divisible by three or one"},
		{name: "One Bit per Pixel", cfg: configs{1, 0, 0, 0, terminal, 1, 1500, "filter", "input", "prefix", logic}, lGate: "xor", lValue: "255"},
		{name: "27 Bits per Pixel", cfg: configs{27, 0, 0, 0, terminal, 1, 1500, "filter", "input", "prefix", logic}, lGate: "xor", lValue: "255", err: "-bits 27 must be smaller than 25"},
		{name: "Terminal only", cfg: configs{3, 0, 0, 0, terminal, 1, 1500, "filter", "input", "prefix", logic}, lGate: "xor", lValue: "255"},
		{name: "Terminal and Timeslize", cfg: configs{3, 0, 0, 0, (terminal | timeslize), 1, 1500, "filter", "input", "prefix", logic}, lGate: "xor", lValue: "255", console: true, err: "-timeslize and -terminal can't be combined"},
		{name: "Fixed Slize", cfg: configs{1, 0, 0, 0, 0, 1, 1500, "filter", "input", "prefix", logic}, lGate: "xor", lValue: "255"},
		{name: "Time Slize", cfg: configs{1, 0, 50, 0, 0, 1, 1500, "filter", "input", "prefix", logic}, lGate: "xor", lValue: "255"},
		{name: "Scale and Terminal", cfg: configs{1, 0, 0, 0, terminal, 2, 1500, "filter", "input", "prefix", logic}, lGate: "xor", lValue: "255", console: true, err: "-scale and -terminal can't be combined"},
		{name: "Time Slize", cfg: configs{1, 0, 50, 0, 0, 0, 1500, "filter", "input", "prefix", logic}, lGate: "xor", lValue: "255", err: "scale factor has to be at least 1"},
		{name: "Time Slize, Terminal and Rebuild", cfg: configs{1, 0, 50, 0, 0, 0, 1500, "filter", "input", "prefix", logic}, lGate: "xor", lValue: "255", console: true, rebuild: true, err: "-terminal, -timeslize and -reverse can't be combined"},
		{name: "Time Slize and Rebuild", cfg: configs{1, 0, 50, 0, 0, 0, 1500, "filter", "input", "prefix", logic}, lGate: "xor", lValue: "255", rebuild: true, err: "-timeslize and -reverse can't be combined"},
		{name: "Terminal and Rebuild", cfg: configs{1, 0, 0, 0, 0, 1, 1500, "filter", "input", "prefix", logic}, lGate: "xor", lValue: "255", console: true, rebuild: true, err: "-terminal and -reverse can't be combined"},
		{name: "Rebuild without file", cfg: configs{1, 0, 0, 0, 0, 1, 1500, "filter", "", "prefix", logic}, lGate: "xor", lValue: "255", console: false, rebuild: true, err: "-file is needed as source"},
		{name: "Jumbo frame", cfg: configs{1, 0, 0, 0, 0, 1, 15000, "filter", "input", "prefix", logic}, lGate: "xor", lValue: "255", err: "limit has to be smallerthan a Jumbo frame"},
		{name: "XOR", cfg: configs{1, 0, 0, 0, terminal, 1, 1500, "filter", "input", "prefix", logic}, lGate: "xor", lValue: "255"},
		{name: "AND", cfg: configs{1, 0, 0, 0, terminal, 1, 1500, "filter", "input", "prefix", logic}, lGate: "and", lValue: "255"},
		{name: "OR", cfg: configs{1, 0, 0, 0, terminal, 1, 1500, "filter", "input", "prefix", logic}, lGate: "or", lValue: "255"},
		{name: "NOT", cfg: configs{1, 0, 0, 0, terminal, 1, 1500, "filter", "input", "prefix", logic}, lGate: "not", lValue: "255"},
		{name: "NAND", cfg: configs{1, 0, 0, 0, terminal, 1, 1500, "filter", "input", "prefix", logic}, lGate: "nand", lValue: "255"},
		{name: "None", cfg: configs{1, 0, 0, 0, terminal, 1, 1500, "filter", "input", "prefix", logic}, lGate: "none", lValue: "255"},
		{name: "-1", cfg: configs{1, 0, 0, 0, terminal, 1, 1500, "filter", "input", "prefix", logic}, lGate: "none", lValue: "-1", err: "-1 is not a valid value"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := checkConfig(&tc.cfg, tc.console, tc.rebuild, tc.lGate, tc.lValue)
			if err != nil {
				if matched, _ := regexp.MatchString(tc.err, err.Error()); matched == false {
					t.Fatalf("Error matching regex: %v \t Got: %v", tc.err, err)
				}
			} else if len(tc.err) != 0 {
				t.Fatalf("Expected error, got none")
			}
		})
	}
}

func TestCreatePixel(t *testing.T) {
	t.Parallel()

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
				t.Fatalf("Expected: r%dg%db%d\t Got: r%dg%db%d", tc.red, tc.green, tc.blue, uint8(r), uint8(g), uint8(b))
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

	unknownFormat, ferr := ioutil.TempFile(tdir, "unknownFormat.pcap")
	if ferr != nil {
		t.Fatal(ferr)
	}
	defer os.Remove(unknownFormat.Name())
	ferr = ioutil.WriteFile(unknownFormat.Name(), []byte(notSvg), 0644)
	if ferr != nil {
		t.Fatal(ferr)
	}
	defer unknownFormat.Close()

	testdir, ferr := ioutil.TempDir(tdir, "TestDir")
	if ferr != nil {
		t.Fatal(ferr)
	}
	defer os.RemoveAll(testdir)

	tests := []struct {
		name   string
		input  string
		filter string
		pcap   bool
		err    string
	}{
		{name: "No Source", input: "", pcap: false, err: "(Source is missing)|(Could not get file information)"},
		{name: "Invalid File", input: "/invalid/file", pcap: false, err: "(No such file or directory)|(Could not get file information)"},
		{name: "Non existing Device", input: "/dev/InvalidDevice", pcap: true, err: "(No such file or directory)|(No such device exists)|(Operation not permitted)"},
		{name: "Invalid Filter", input: fmt.Sprintf("%s", fakePcap.Name()), pcap: false, filter: "noFilter", err: "syntax error"},
		{name: "Unknown file format", input: fmt.Sprintf("%s", unknownFormat.Name()), pcap: true, err: "unknown file format"},
		{name: "No Errors", input: fmt.Sprintf("%s", fakePcap.Name())},
		{name: "Folder As Input", input: testdir, err: "Can not handle"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := initSource(tc.input, tc.filter, tc.pcap)
			if err != nil {
				if matched, _ := regexp.MatchString(tc.err, err.Error()); matched == false {
					t.Fatalf("Error matching regex: %v \t Got: %v", tc.err, err)
				} else {
					return
				}
				t.Fatalf("Expected no error, got: %v", err)
			} else if len(tc.err) != 0 {
				t.Fatalf("Expected error, got none")
			}
		})
	}

}

func TestCreateImage(t *testing.T) {

	dir, err := ioutil.TempDir("", "TestCreateImage")
	if err != nil {
		t.Fatalf("Could not create temporary directory: %v", err)
	}

	logic := logicOp{
		name:  "none",
		gate:  nil,
		value: 0,
	}

	defer os.RemoveAll(dir)
	tests := []struct {
		name     string
		filename string
		width    int
		height   int
		cfg      configs
		data     string
	}{
		{name: "No Filename", filename: fmt.Sprintf("%s/test.svg", dir), cfg: configs{24, 0, 0, 0, solder, 1, 1500, "filter", "input", fmt.Sprintf("%s/solid", dir), logic}, data: "<rect x=\"0\" y=\"0\" width=\"1\" height=\"1\" style=\"fill:rgb(0,0,0)\" />"},
		{name: "Just directory name", filename: dir, cfg: configs{24, 0, 0, 0, solder, 1, 1500, "filter", "input", fmt.Sprintf("%s/solid", dir), logic}, data: "<rect x=\"0\" y=\"0\" width=\"1\" height=\"1\" style=\"fill:rgb(0,0,0)\" />"},
		{name: "No Data", filename: fmt.Sprintf("%s/test.svg", dir), cfg: configs{24, 0, 0, 0, solder, 1, 1500, "filter", "input", fmt.Sprintf("%s/solid", dir), logic}},
		{name: "Without errors from File", filename: fmt.Sprintf("%s/test.svg", dir), cfg: configs{24, 0, 0, 0, solder, 1, 1500, "filter", "input", fmt.Sprintf("%s/solid", dir), logic}, data: "<rect x=\"0\" y=\"0\" width=\"1\" height=\"1\" style=\"fill:rgb(0,0,0)\" />"},
		{name: "Without errors from Dev", filename: fmt.Sprintf("%s/test.svg", dir), cfg: configs{24, 0, 0, 0, solder, 1, 1500, "filter", "", fmt.Sprintf("%s/solid", dir), logic}, data: "<rect x=\"0\" y=\"0\" width=\"1\" height=\"1\" style=\"fill:rgb(0,0,0)\" />"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			createImage(tc.filename, tc.width, tc.height, tc.data, tc.cfg)
		})
	}
}

func TestCreateVisualization(t *testing.T) {
	dir, err := ioutil.TempDir("", "TestCreateVisualization")
	if err != nil {
		t.Fatalf("Could not create temporary directory: %v", err)
	}
	defer os.RemoveAll(dir)

	logic := logicOp{
		name:  "none",
		gate:  nil,
		value: 0,
	}

	tests := []struct {
		name    string
		content []data
		xLimit  uint
		prefix  string
		num     uint
		cfg     configs
		err     string
	}{
		{name: "No Data", xLimit: 1, prefix: fmt.Sprintf("%s/noData", dir), num: 1, cfg: configs{1, 0, 0, 0, solder, 1, 1500, "filter", "input", "prefix", logic}, err: "No image data provided"},
		{name: "Solid image", content: []data{{toa: 0, payload: []byte{0xCA, 0xFE, 0xBA, 0xBE}}}, xLimit: 1, prefix: fmt.Sprintf("%s/solid", dir), num: 1, cfg: configs{24, 0, 0, 0, solder, 1, 1500, "filter", "input", fmt.Sprintf("%s/solid", dir), logic}},
		{name: "Timeslize image", content: []data{{toa: 0, payload: []byte{0xCA, 0xFE, 0xBA, 0xBE}}}, xLimit: 1, prefix: fmt.Sprintf("%s/timeslize", dir), num: 1, cfg: configs{24, 0, 0, 0, timeslize, 1, 1500, "filter", "input", fmt.Sprintf("%s/timeslize", dir), logic}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g, _ := errgroup.WithContext(context.Background())
			createVisualization(g, tc.content, tc.num, tc.cfg)
		})
	}
}

func TestCreateTerminalVisualization(t *testing.T) {

	logic := logicOp{
		name:  "none",
		gate:  nil,
		value: 0,
	}
	tests := []struct {
		name string
		pkt1 data
		pkt2 data
		cfg  configs
	}{
		{name: "bytePos >= pkt1Len", pkt1: data{toa: 0, payload: []byte{0x01}}, pkt2: data{toa: 0, payload: []byte{0xCA, 0xFE, 0xC0, 0x00, 0x10, 0xFF, 0xC0, 0xFF, 0xEE}}, cfg: configs{3, 0, 0, 0, timeslize, 1, 1500, "filter", "input", "prefix", logic}},
		{name: "bytePos >= pkt2Len", pkt1: data{toa: 0, payload: []byte{0xCA, 0xFE, 0xC0, 0x00, 0x10, 0xFF, 0xC0, 0xFF, 0xEE}}, pkt2: data{toa: 0, payload: []byte{0x01}}, cfg: configs{3, 0, 0, 0, timeslize, 1, 1500, "filter", "input", "prefix", logic}},
		{name: "pkt1Len == pkt2Len", pkt1: data{toa: 0, payload: []byte{0xCA, 0xFE, 0xC0, 0x00, 0x10, 0xFF, 0xC0, 0xFF, 0xEE}}, pkt2: data{toa: 0, payload: []byte{0xCA, 0xFE, 0xC0, 0x00, 0x10, 0xFF, 0xC0, 0xFF, 0xEE}}, cfg: configs{3, 0, 0, 0, timeslize, 1, 1500, "filter", "input", "prefix", logic}},
		{name: "pkt1Len == 0", pkt1: data{toa: 0, payload: []byte{}}, pkt2: data{toa: 0, payload: []byte{0xCA, 0xFE, 0xC0, 0x00, 0x10, 0xFF, 0xC0, 0xFF, 0xEE}}, cfg: configs{3, 0, 0, 0, timeslize, 1, 1500, "filter", "input", "prefix", logic}},
		{name: "pkt2Len == 0", pkt1: data{toa: 0, payload: []byte{0xCA, 0xFE, 0xC0, 0x00, 0x10, 0xFF, 0xC0, 0xFF, 0xEE}}, pkt2: data{toa: 0, payload: []byte{}}, cfg: configs{3, 0, 0, 0, timeslize, 1, 1500, "filter", "input", "prefix", logic}},
		{name: "bytePos > xlimit", pkt1: data{toa: 0, payload: []byte{0xCA, 0xFE, 0xC0, 0x00, 0x10, 0xFF, 0xC0, 0xFF, 0xEE}}, pkt2: data{toa: 0, payload: []byte{0xCA, 0xFE, 0xC0, 0x00, 0x10, 0xFF, 0xC0, 0xFF, 0xEE}}, cfg: configs{24, 0, 0, 2, timeslize, 1, 1500, "filter", "input", "prefix", logic}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			createTerminalVisualization(tc.pkt1, tc.pkt2, tc.cfg)
		})
	}
}

func TestCreateBytes(t *testing.T) {
	t.Parallel()

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
				t.Fatalf("Expected: %v \t Got: %v", tc.ret, ret)
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

	pipeline := func(payload []byte, operand byte) []byte {
		return payload
	}

	noneLogic := logicOp{
		name:  "none",
		gate:  nil,
		value: 0,
	}

	pipelineLogic := logicOp{
		name:  "pipeline",
		gate:  pipeline,
		value: 0,
	}

	tests := []struct {
		name string
		cfg  configs
		err  string
	}{
		{name: "solder", cfg: configs{1, 2, 0, 0, solder, 1, 1500, "", fmt.Sprintf("%s", fakePcap.Name()), fmt.Sprintf("%s/solder", tdir), pipelineLogic}},
		{name: "terminal", cfg: configs{24, 0, 0, 0, terminal, 1, 1500, "", fmt.Sprintf("%s", fakePcap.Name()), fmt.Sprintf("%s/terminal", tdir), pipelineLogic}},
		{name: "timeslize", cfg: configs{1, 2, 0, 0, timeslize, 1, 1500, "", fmt.Sprintf("%s", fakePcap.Name()), fmt.Sprintf("%s/timeslize", tdir), pipelineLogic}},
		{name: "No Source", cfg: configs{1, 2, 0, 0, timeslize, 1, 1500, "", "", fmt.Sprintf("%s/NoSource", tdir), noneLogic}, err: "(Source is missing)|(Could not get file information)"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g, _ := errgroup.WithContext(context.Background())
			err := visualize(g, tc.cfg)
			if err != nil {
				if matched, _ := regexp.MatchString(tc.err, err.Error()); matched == false {
					t.Fatalf("Error matching regex: %v \t Got: %v", tc.err, err)
				}
			} else if len(tc.err) != 0 {
				t.Fatalf("Expected error, got none")
			}
		})
	}
}

func TestMain(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "without options", args: []string{"cmd"}},
		//		{name: "help", args: []string{"cmd", "-help"}},
		//		{name: "version", args: []string{"cmd", "-version"}},
	}
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			os.Args = tc.args
			main()
		})
	}
}

func TestGetOperand(t *testing.T) {
	tests := []struct {
		name string
		val  string
		b    byte
		e    string
	}{
		{name: "-1", val: "-1", b: byte(0), e: "-1 is not a valid value"},
		{name: "0", val: "0", b: byte(0)},
		{name: "1", val: "1", b: byte(1)},
		{name: "254", val: "254", b: byte(254)},
		{name: "255", val: "255", b: byte(255)},
		{name: "256", val: "256", b: byte(0), e: "is not a valid value"},
		{name: "0x00", val: "0x00", b: byte(0)},
		{name: "a", val: "a", b: byte(10)},
		{name: "0xFF", val: "0xFF", b: byte(255)},
		{name: "1.1", val: "1.1", b: byte(0), e: "Could not convert"},
		{name: "1,1", val: "1,1", b: byte(0), e: "Could not convert"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b, e := getOperand(tc.val)
			if e != nil {
				if matched, _ := regexp.MatchString(tc.e, e.Error()); matched == false {
					t.Fatalf("Error matching regex: %v \t Got: %v", tc.e, e)
				}
			} else if len(tc.e) != 0 {
				t.Fatalf("Expected error, got none")
			}
			if b != tc.b {
				t.Fatalf("Missmatched return\tExpected: %v \t Got: %v", tc.b, b)
			}
		})
	}
}

func TestOpXor(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		payload []byte
		operand byte
		r       []byte
	}{
		{name: "0x00", payload: []byte{0x00, 0xFF, 0xAA, 0x55}, operand: 0x00, r: []byte{0x00, 0xFF, 0xAA, 0x55}},
		{name: "0xFF", payload: []byte{0x00, 0xFF, 0xAA, 0x55}, operand: 0xFF, r: []byte{0xFF, 0x00, 0x55, 0xAA}},
		{name: "0x0F", payload: []byte{0x00, 0xFF, 0xAA, 0x55}, operand: 0x0F, r: []byte{0x0F, 0xF0, 0xA5, 0x5A}},
		{name: "0xF0", payload: []byte{0x00, 0xFF, 0xAA, 0x55}, operand: 0xF0, r: []byte{0xF0, 0x0F, 0x5A, 0xA5}}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := opXor(tc.payload, tc.operand)
			if bytes.Equal(tc.r, r) == false {
				t.Fatalf("Expected: %v \t Got: %v", tc.r, r)
			}
		})
	}
}

func TestOpOr(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		payload []byte
		operand byte
		r       []byte
	}{
		{name: "0x00", payload: []byte{0x00, 0xFF, 0xAA, 0x55}, operand: 0x00, r: []byte{0x00, 0xFF, 0xAA, 0x55}},
		{name: "0xFF", payload: []byte{0x00, 0xFF, 0xAA, 0x55}, operand: 0xFF, r: []byte{0xFF, 0xFF, 0xFF, 0xFF}},
		{name: "0x0F", payload: []byte{0x00, 0xFF, 0xAA, 0x55}, operand: 0x0F, r: []byte{0x0F, 0xFF, 0xAF, 0x5F}},
		{name: "0xF0", payload: []byte{0x00, 0xFF, 0xAA, 0x55}, operand: 0xF0, r: []byte{0xF0, 0xFF, 0xFA, 0xF5}}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := opOr(tc.payload, tc.operand)
			if bytes.Equal(tc.r, r) == false {
				t.Fatalf("Expected: %v \t Got: %v", tc.r, r)
			}
		})
	}
}

func TestOpAnd(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		payload []byte
		operand byte
		r       []byte
	}{
		{name: "0x00", payload: []byte{0x00, 0xFF, 0xAA, 0x55}, operand: 0x00, r: []byte{0x00, 0x00, 0x00, 0x00}},
		{name: "0xFF", payload: []byte{0x00, 0xFF, 0xAA, 0x55}, operand: 0xFF, r: []byte{0x00, 0xFF, 0xAA, 0x55}},
		{name: "0x0F", payload: []byte{0x00, 0xFF, 0xAA, 0x55}, operand: 0x0F, r: []byte{0x00, 0x0F, 0x0A, 0x05}},
		{name: "0xF0", payload: []byte{0x00, 0xFF, 0xAA, 0x55}, operand: 0xF0, r: []byte{0x00, 0xF0, 0xA0, 0x50}}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := opAnd(tc.payload, tc.operand)
			if bytes.Equal(tc.r, r) == false {
				t.Fatalf("Expected: %v \t Got: %v", tc.r, r)
			}
		})
	}
}

func TestOpNot(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		payload []byte
		operand byte
		r       []byte
	}{
		{name: "0x00", payload: []byte{0x00, 0xFF, 0xAA, 0x55}, operand: 0x00, r: []byte{0xFF, 0x00, 0x55, 0xAA}},
		{name: "0xFF", payload: []byte{0x00, 0xFF, 0xAA, 0x55}, operand: 0xFF, r: []byte{0xFF, 0x00, 0x55, 0xAA}},
		{name: "0x0F", payload: []byte{0x00, 0xFF, 0xAA, 0x55}, operand: 0x0F, r: []byte{0xFF, 0x00, 0x55, 0xAA}},
		{name: "0xF0", payload: []byte{0x00, 0xFF, 0xAA, 0x55}, operand: 0xF0, r: []byte{0xFF, 0x00, 0x55, 0xAA}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := opNot(tc.payload, tc.operand)
			if bytes.Equal(tc.r, r) == false {
				t.Fatalf("Expected: %v \t Got: %v", tc.r, r)
			}
		})
	}
}

func TestOpNand(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		payload []byte
		operand byte
		r       []byte
	}{
		{name: "0x00", payload: []byte{0x00, 0xFF, 0xAA, 0x55}, operand: 0x00, r: []byte{0x00, 0xFF, 0xAA, 0x55}},
		{name: "0xFF", payload: []byte{0x00, 0xFF, 0xAA, 0x55}, operand: 0xFF, r: []byte{0x00, 0x0, 0x00, 0x00}},
		{name: "0x0F", payload: []byte{0x00, 0xFF, 0xAA, 0x55}, operand: 0x0F, r: []byte{0x00, 0xF0, 0xA0, 0x50}},
		{name: "0xF0", payload: []byte{0x00, 0xFF, 0xAA, 0x55}, operand: 0xF0, r: []byte{0x00, 0x0F, 0x0A, 0x05}}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := opNand(tc.payload, tc.operand)
			if bytes.Equal(tc.r, r) == false {
				t.Fatalf("Expected: %v \t Got: %v", tc.r, r)
			}
		})
	}
}

func TestOpDefault(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		payload []byte
		operand byte
		r       []byte
	}{
		{name: "0x00", payload: []byte{0x00, 0xFF, 0xAA, 0x55}, operand: 0x00, r: []byte{0x00, 0xFF, 0xAA, 0x55}},
		{name: "0xFF", payload: []byte{0x00, 0xFF, 0xAA, 0x55}, operand: 0xFF, r: []byte{0x00, 0xFF, 0xAA, 0x55}},
		{name: "0x0F", payload: []byte{0x00, 0xFF, 0xAA, 0x55}, operand: 0x0F, r: []byte{0x00, 0xFF, 0xAA, 0x55}},
		{name: "0xF0", payload: []byte{0x00, 0xFF, 0xAA, 0x55}, operand: 0xF0, r: []byte{0x00, 0xFF, 0xAA, 0x55}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := opDefault(tc.payload, tc.operand)
			if bytes.Equal(tc.r, r) == false {
				t.Fatalf("Expected: %v \t Got: %v", tc.r, r)
			}
		})
	}
}

func TestRun(t *testing.T) {

	logic := logicOp{
		name:  "none",
		gate:  nil,
		value: 0,
	}

	tdir, ferr := ioutil.TempDir("", "run")
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

	validSvgFile003, err := ioutil.TempFile(tdir, "validSvg003.svg")
	if err != nil {
		t.Fatalf("Could not create temporary file: %v", err)
	}
	defer os.Remove(validSvgFile003.Name())

	validSvgFile003.WriteString(validSvg003)
	if err := validSvgFile003.Close(); err != nil {
		t.Fatalf("Could not close temporary file: %v", err)
	}

	tests := []struct {
		name string
		cfg  configs
		e    string
	}{
		{name: "No source", cfg: configs{2, 0, 0, 0, terminal, 1, 1500, "filter", "", "prefix", logic}, e: "No such file or directory"},
		{name: "terminal", cfg: configs{2, 0, 0, 0, reverse, 1, 1500, "", fmt.Sprintf("%s", fakePcap.Name()), "prefix", logic}},
		{name: "reverse", cfg: configs{2, 0, 0, 0, reverse, 1, 1500, "", fmt.Sprintf("%s", validSvgFile003.Name()), "prefix", logic}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := run(tc.cfg)
			if e != nil {
				if matched, _ := regexp.MatchString(tc.e, e.Error()); matched == false {
					t.Fatalf("Error matching regex: %v \t Got: %v", tc.e, e)
				}
			} else if len(tc.e) != 0 {
				t.Fatalf("Expected error, got none")
			}
		})
	}
}

func BenchmarkLogicOperations(b *testing.B) {
	var payloads = []struct {
		name  string
		bytes []byte
	}{
		{"4", []byte{0x00, 0xFF, 0xAA, 0x55}},
		{"8", []byte{0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55}},
		{"32", []byte{0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55}},
		{"64", []byte{0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55}},
		{"128", []byte{0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55}},
		{"256", []byte{0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55, 0x00, 0xFF, 0xAA, 0x55}},
	}
	var funcs = []struct {
		name    string
		operand byte
		f       func(payload []byte, operand byte) []byte
	}{
		{"xor - 0xFF", 0xFF, opXor},
		{"xor - 0xF0", 0xF0, opXor},
		{"xor - 0x0F", 0x0F, opXor},
		{"xor - 0x00", 0x00, opXor},
		{"or - 0xFF", 0xFF, opOr},
		{"or - 0xF0", 0xF0, opOr},
		{"or - 0x0F", 0x0F, opOr},
		{"or - 0x00", 0x00, opOr},
		{"and - 0xFF", 0xFF, opAnd},
		{"and - 0xF0", 0xF0, opAnd},
		{"and - 0x0F", 0x0F, opAnd},
		{"and - 0x00", 0x00, opAnd},
		{"not - 0xFF", 0xFF, opNot},
		{"not - 0xF0", 0xF0, opNot},
		{"not - 0x0F", 0x0F, opNot},
		{"not - 0x00", 0x00, opNot},
		{"nand - 0xFF", 0xFF, opNand},
		{"nand - 0xF0", 0xF0, opNand},
		{"nand - 0x0F", 0x0F, opNand},
		{"nand - 0x00", 0x00, opNand},
		{"default - 0xFF", 0xFF, opDefault},
		{"default - 0xF0", 0xF0, opDefault},
		{"default - 0x0F", 0x0F, opDefault},
		{"default - 0x00", 0x00, opDefault},
	}
	for _, f := range funcs {
		for _, p := range payloads {
			b.Run(fmt.Sprintf("%s - %s", f.name, p.name), func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					bytes := f.f(p.bytes, f.operand)
					for range bytes {
					}
				}
			})
		}
	}
}
