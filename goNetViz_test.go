package main

import "testing"

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
		name string
		cfg  configs
		err  string
	}{
		// Testing different output stiles
		{name: "Two Bits per Pixel", cfg: configs{2, 0, 0, 0, TERMINAL}, err: "-bits 2 is not divisible by three or one"},
		{name: "One Bit per Pixel", cfg: configs{1, 0, 0, 0, TERMINAL}},
		{name: "27 Bits per Pixel", cfg: configs{27, 0, 0, 0, TERMINAL}, err: "-bits 27 must be smaller than 25"},
		{name: "Terminal only", cfg: configs{3, 0, 0, 0, TERMINAL}},
		{name: "Terminal and Timeslize", cfg: configs{3, 0, 0, 0, (TERMINAL | TIMESLIZES)}, err: "-timeslize and -terminal can't be combined"},
		{name: "Fixed Slize", cfg: configs{1, 0, 0, 0, 0}},
		{name: "Time Slize", cfg: configs{1, 0, 50, 0, 0}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := checkConfig(&tc.cfg)

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
		{"Byte Boundary", []byte{0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A}, 0, 6, 1, 255, 255, 255},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, g, b := createPixel(tc.packet, &(tc.byteP), &(tc.bitP), tc.bpP)
			if uint8(r) != tc.red || uint8(g) != tc.green || uint8(b) != tc.blue {
				t.Errorf("Expected: r%dg%db%d\t Got: r%dg%db%d", tc.red, tc.green, tc.blue,uint8(r), uint8(g), uint8(b))
			}
		})
	}
}

func TestInitSource(t *testing.T) {
	tests := []struct {
		name	string
		dev	string
		file	string
		filter	*string
		err	string
	}{
		{name: "No Source", dev: "", file: "", filter: nil, err: "Source is missing\n"},
		{name: "Invalid File", dev: "", file: "/invalid/file", filter: nil, err: "/invalid/file: No such file or directory"},
		{name: "Non existing Device", dev: "/dev/InvalidDevice", file: "", filter: nil, err: "/dev/InvalidDevice: No such device exists (No such device exists)"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := initSource(&(tc.dev), &(tc.file), tc.filter)
			if err.Error() != tc.err {
					t.Errorf("Expected: %v \t Got: %v", tc.err, err)
			}
		})
	}

}

func TestCreateImage(t *testing.T){
	tests := []struct {
		name		string
		filename	string
		width		int
		height		int
		data		string
		err		string
	}{
		{name: "No Filename", filename: "", err: "Could not open image: open : no such file or directory"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := createImage(tc.filename, tc.width, tc.height, tc.data)
			if err.Error() != tc.err {
					t.Errorf("Expected: %v \t Got: %v", tc.err, err)
			}
		})
	}
}
