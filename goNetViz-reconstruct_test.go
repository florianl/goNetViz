package main

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"sync"
	"testing"

	"golang.org/x/sync/errgroup"
)

func TestReconstruct(t *testing.T) {
	tdir, ferr := ioutil.TempDir("", "reconstruct")
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

	logic := logicOp{
		name:  "none",
		gate:  nil,
		value: 0,
	}

	tests := []struct {
		name string
		cfg  configs
		err  string
	}{
		{name: "solder", cfg: configs{1, 2, 0, 0, solder, 1, 1500, "", fakePcap.Name(), fmt.Sprintf("%s/solder", tdir), logic}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g, _ := errgroup.WithContext(context.Background())
			err := reconstruct(g, tc.cfg)
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

func TestCreatePcap(t *testing.T) {
	dir, err := ioutil.TempDir("", "TestCreatePcap")
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
		payload []byte
		cfg     configs
		err     string
	}{
		{name: "Simple", cfg: configs{1, 0, 0, 0, 0, 1, 1500, "", "", fmt.Sprintf("%s/simple", dir), logic}, payload: []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05}},
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

func TestCreatePacket(t *testing.T) {
	dir, err := ioutil.TempDir("", "TestCreatePcap")
	if err != nil {
		t.Fatalf("Could not create temporary directory: %v", err)
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
		{name: "2 BitsPerPixel", recv: []byte{}, packet: []int{8, 16, 32, 64, 128}, bpP: 2, err: "this format is not supported so far"},
		{name: "1 BitPerPixel", recv: []byte{1, 8}, packet: []int{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0}, bpP: 1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ch := make(chan []byte)
			var wg sync.WaitGroup
			wg.Add(1)
			var recv []byte
			go func() {
				defer wg.Done()
				v := <-ch
				recv = append(recv, v...)
				close(ch)
			}()
			err := createPacket(ch, tc.packet, tc.bpP)
			if err != nil {
				if matched, _ := regexp.MatchString(tc.err, err.Error()); matched == false {
					t.Fatalf("Error matching regex: %v \t Got: %v", tc.err, err)
				} else {
					wg.Done()
					return
				}
				t.Fatalf("Expected no error, got: %v", err)
			} else if len(tc.err) != 0 {
				t.Fatalf("Expected error, got none")
			}
			wg.Wait()
			if !bytes.Equal(recv, tc.recv) {
				t.Fatalf("Expected: %v \t Got: %v", tc.recv, recv)
			}
		})
	}
}

func TestExtractInformation(t *testing.T) {
	dir, err := ioutil.TempDir("", "TestExtractInformation")
	if err != nil {
		t.Fatalf("Could not create temporary directory: %v", err)
	}
	defer os.RemoveAll(dir)

	notSvgFile, err := ioutil.TempFile(dir, "notSvg.svg")
	if err != nil {
		t.Fatalf("Could not create temporary file: %v", err)
	}
	defer os.Remove(notSvgFile.Name())

	notSvgFile.WriteString(notSvg)
	if err := notSvgFile.Close(); err != nil {
		t.Fatalf("Could not close temporary file: %v", err)
	}

	withoutCommentFile, err := ioutil.TempFile(dir, "withoutComment.svg")
	if err != nil {
		t.Fatalf("Could not create temporary file: %v", err)
	}
	defer os.Remove(withoutCommentFile.Name())

	withoutCommentFile.WriteString(withoutComment)
	if err := withoutCommentFile.Close(); err != nil {
		t.Fatalf("Could not close temporary file: %v", err)
	}

	validSvgFile003, err := ioutil.TempFile(dir, "validSvg003.svg")
	if err != nil {
		t.Fatalf("Could not create temporary file: %v", err)
	}
	defer os.Remove(validSvgFile003.Name())

	validSvgFile003.WriteString(validSvg003)
	if err := validSvgFile003.Close(); err != nil {
		t.Fatalf("Could not close temporary file: %v", err)
	}

	validSvgFile004, err := ioutil.TempFile(dir, "validSvg004.svg")
	if err != nil {
		t.Fatalf("Could not create temporary file: %v", err)
	}
	defer os.Remove(validSvgFile004.Name())

	validSvgFile004.WriteString(validSvg004)
	if err := validSvgFile004.Close(); err != nil {
		t.Fatalf("Could not close temporary file: %v", err)
	}

	invalidVersionFile, err := ioutil.TempFile(dir, "invalidVersion.svg")
	if err != nil {
		t.Fatalf("Could not create temporary file: %v", err)
	}
	defer os.Remove(invalidVersionFile.Name())

	invalidVersionFile.WriteString(invalidVersion)
	if err := invalidVersionFile.Close(); err != nil {
		t.Fatalf("Could not close temporary file: %v", err)
	}

	logic := logicOp{
		name:  "none",
		gate:  nil,
		value: 0,
	}

	tests := []struct {
		name string
		cfg  configs
		recv []byte
		err  string
	}{
		{name: "No file", cfg: configs{1, 0, 0, 0, 0, 1, 1500, "", "noFile", fmt.Sprintf("%s/noFile", dir), logic}, err: "could not open file"},
		{name: "Not a svg", cfg: configs{1, 0, 0, 0, 0, 1, 1500, "", notSvgFile.Name(), fmt.Sprintf("%s/not_a_svg", dir), logic}, err: "no end of header found"},
		{name: "Without Comment", cfg: configs{1, 0, 0, 0, 0, 1, 1500, "", withoutCommentFile.Name(), fmt.Sprintf("%s/without_comment", dir), logic}, err: "no end of header found"},
		{name: "Valid003 svg", cfg: configs{1, 0, 0, 0, 0, 1, 1500, "", validSvgFile003.Name(), fmt.Sprintf("%s/valid_003_svg", dir), logic}, recv: []byte{0, 0}},
		{name: "Valid004 svg", cfg: configs{1, 0, 0, 0, 0, 1, 1500, "", validSvgFile004.Name(), fmt.Sprintf("%s/valid_004_svg", dir), logic}, err: "can't decode version"},
		{name: "Invalid version", cfg: configs{1, 0, 0, 0, 0, 1, 1500, "", invalidVersionFile.Name(), fmt.Sprintf("%s/invalid_version", dir), logic}, err: "unrecognized version"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g, _ := errgroup.WithContext(context.Background())
			var wg sync.WaitGroup
			wg.Add(1)
			ch := make(chan []byte)
			var recv []byte
			go func() {
				defer wg.Done()
				for i, ok := <-ch; ok; i, ok = <-ch {
					recv = append(recv, i...)
				}
			}()
			err := extractInformation(g, ch, tc.cfg)
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
			wg.Wait()
			if !bytes.Equal(recv, tc.recv) {
				t.Fatalf("Expected: %v \t Got: %v", tc.recv, recv)
			}
		})
	}
}
