package main

import "testing"

func TestGetBitsFromPacket(t *testing.T) {

	var bytePos int
	var bitPos int
	tests := []struct {
		packet []byte
		bpP    uint
		ret    uint8
	}{
		{[]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, 24, 255},
		{[]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, 12, 240},
		{[]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, 9, 14},
		{[]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, 3, 1},
		{[]byte{0x00, 0x00, 0x00, 0x00, 0x00}, 24, 0},
		{[]byte{0x00, 0x00, 0x00, 0x00, 0x00}, 12, 0},
		{[]byte{0x00, 0x00, 0x00, 0x00, 0x00}, 9, 0},
		{[]byte{0x00, 0x00, 0x00, 0x00, 0x00}, 3, 0},
	}

	for _, test := range tests {
		res := getBitsFromPacket(test.packet, &bytePos, &bitPos, test.bpP)
		if res != test.ret {
			t.Errorf("Input: %d Expected: %d \t Got %d", test.packet, test.ret, res)
		}
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
			res := checkConfig(tc.cfg)

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
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := createPixel(tc.packet, &(tc.byteP), &(tc.bitP), tc.bpP)
			r, g, b, _ := c.RGBA()
			if uint8(r) != tc.red || uint8(g) != tc.green || uint8(b) != tc.blue {
				t.Errorf("Expected: ", tc.red, tc.green, tc.blue, "\t Got: ", uint8(r), uint8(g), uint8(b))
			}
		})
	}
}
