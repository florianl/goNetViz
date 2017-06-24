package main

import "testing"
import (
	"errors"
)

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
		cfg configs
		ret error
	}{
		// Testing different output stiles
		{configs{3, 0, 0, 0, TERMINAL}, nil},
		{configs{3, 0, 0, 0, (TERMINAL | TIMESLIZES)}, errors.New("-timeslize and -terminal can't be combined")},
		{configs{3, 0, 25, 0, TERMINAL}, errors.New("-timeslize and -terminal can't be combined")},
		{configs{3, 0, 0, 0, TIMESLIZES}, nil},
		{configs{3, 0, 0, 0, 0}, nil},
	}

	for i, test := range tests {
		t.Logf("Testing %d. config\n", i)
		res := checkConfig(test.cfg)
		if res != nil && test.ret != nil {
			t.Log("Expected: ", test.ret, "\t Got: ", res)
		} else if res != nil && test.ret == nil {
			t.Errorf("Expected: %v \t Got: %v", test.ret, res)
		}
	}

}
