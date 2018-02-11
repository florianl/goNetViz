package main

import (
	"bytes"
	"context"
	"fmt"
	"golang.org/x/sync/errgroup"
	"io/ioutil"
	"os"
	"regexp"
	"sync"
	"testing"
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

	tests := []struct {
		name string
		cfg  configs
		err  string
	}{
		{name: "solder", cfg: configs{1, 2, 0, 0, solder, 1, 1500, "", "", fmt.Sprintf("%s", fakePcap.Name()), fmt.Sprintf("%s/solder", tdir), nil, 0}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g, _ := errgroup.WithContext(context.Background())
			err := reconstruct(g, tc.cfg)
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

func TestCreatePcap(t *testing.T) {
	dir, err := ioutil.TempDir("", "TestCreatePcap")
	if err != nil {
		t.Fatalf("Could not create temporary directory: %v", err)
	}
	defer os.RemoveAll(dir)
	tests := []struct {
		name    string
		payload []byte
		cfg     configs
		err     string
	}{
		{name: "Simple", cfg: configs{1, 0, 0, 0, 0, 1, 1500, "", "", "", fmt.Sprintf("%s/simple", dir), nil, 0}, payload: []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05}},
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
		{name: "2 BitsPerPixel", recv: []byte{}, packet: []int{8, 16, 32, 64, 128}, bpP: 2, err: "This format is not supported so far"},
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
				select {
				case v, _ := <-ch:
					recv = append(recv, v...)
				}
				close(ch)
			}()
			err := createPacket(ch, tc.packet, tc.bpP)
			if err != nil {
				if matched, _ := regexp.MatchString(tc.err, err.Error()); matched == false {
					t.Fatalf("Error matching regex: %v \t Got: %v", tc.err, err)
				}
				wg.Done()
			} else if len(tc.err) != 0 {
				t.Fatalf("Expected error, got none")
			}
			wg.Wait()
			if bytes.Compare(recv, tc.recv) != 0 {
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

	validSvgFile, err := ioutil.TempFile(dir, "validSvg.svg")
	if err != nil {
		t.Fatalf("Could not create temporary file: %v", err)
	}
	defer os.Remove(validSvgFile.Name())

	validSvgFile.WriteString(validSvg)
	if err := validSvgFile.Close(); err != nil {
		t.Fatalf("Could not close temporary file: %v", err)
	}

	tests := []struct {
		name string
		cfg  configs
		recv []byte
		err  string
	}{
		{name: "No file", cfg: configs{1, 0, 0, 0, 0, 1, 1500, "", "", "noFile", fmt.Sprintf("%s/noFile", dir), nil, 0}, err: "Could not open file"},
		{name: "Not a svg", cfg: configs{1, 0, 0, 0, 0, 1, 1500, "", "", fmt.Sprintf("%s", notSvgFile.Name()), fmt.Sprintf("%s/not_a_svg", dir), nil, 0}},
		{name: "Without Comment", cfg: configs{1, 0, 0, 0, 0, 1, 1500, "", "", fmt.Sprintf("%s", withoutCommentFile.Name()), fmt.Sprintf("%s/without_comment", dir), nil, 0}},
		{name: "Valid svg", cfg: configs{1, 0, 0, 0, 0, 1, 1500, "", "", fmt.Sprintf("%s", validSvgFile.Name()), fmt.Sprintf("%s/valid_svg", dir), nil, 0}, recv: []byte{0, 0}},
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
				}
				wg.Done()
			} else if len(tc.err) != 0 {
				t.Fatalf("Expected error, got none")
			}
			wg.Wait()
			if bytes.Compare(recv, tc.recv) != 0 {
				t.Fatalf("Expected: %v \t Got: %v", tc.recv, recv)
			}
		})
	}
}
