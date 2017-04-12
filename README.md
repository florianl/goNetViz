goNetViz
========

This is `goNetViz` and it is written in [golang](https://golang.org/).
`goNetViz` visualizes your network traffic, either by reading a file or
attaching to a network interface.

        $ ./main -help
          -count uint
                Number of packets to process (default 10)
          -file string
                Choose a file for offline processing
          -filter string
                Set a specific filter
          -help
                Show help
          -interface string
                Choose an interface for online processing
          -list_interfaces
                List available interfaces
          -output string
                Name of the resulting image (default "image.png")
          -version
                Show version

Building
--------

        $ git clone git@github.com:florianl/goNetViz.git
          Cloning into 'goNetViz'...
          [...]
        $ cd goNetViz/
        $ export GOPATH=$HOME/go
        $ go get github.com/google/gopacket
          [...]
        $ go build main.go
          [...]
        $ ./main
          [...]

License
-------

Copyright 2017 Florian Lehner <dev@der-flo.net>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
