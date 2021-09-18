goNetViz
========

This is `goNetViz` and it is written in [golang](https://golang.org/).
`goNetViz` visualizes your network traffic, either by reading a file or
attaching to a network interface.

[![Coverage Status](https://coveralls.io/repos/github/florianl/goNetViz/badge.svg?branch=master)](https://coveralls.io/github/florianl/goNetViz?branch=master)


        $ ./goNetViz -help
          ./goNetViz [-bits ...] [-count ...] [-file ... | -interface ...] [-filter ...] [-list_interfaces] [-help] [-prefix ...] [-size ... | -timeslize ... | -terminal] [-version]
          -bits uint
               Number of bits per pixel. It must be divisible by three and smaller than 25 or 1.
               To get black/white results, choose 1 as input. (default 24)
          -count uint
               Number of packets to process.
               If argument is 0 the limit is removed. (default 25)
          -file string
               Choose a file for offline processing.
          -filter string
               Set a specific filter.
          -help
               Show this help.
          -interface string
               Choose an interface for online processing.
          -limit uint
               Maximim number of bytes per packet.
               If your MTU is higher than the default value of 1500 you might change this value. (default 1500)
          -list_interfaces
               List available interfaces.
          -logicGate string
               Logical operation for the input
          -logicValue string
               Operand for the logical operation (default "255")
          -prefix string
               Prefix of the resulting image. (default "image")
          -reverse
               Create a pcap from a svg
          -scale uint
               Scaling factor for output.
               Works not for output on terminal. (default 1)
          -size uint
               Number of packets per image.
               If argument is 0 the limit is removed. (default 25)
          -terminal
               Visualize output on terminal.
          -timeslize uint
               Number of microseconds per resulting image.
               So each pixel of the height of the resulting image represents one microsecond.
          -version
               Show version.

Building
--------

        $ git clone git@github.com:florianl/goNetViz.git
          Cloning into 'goNetViz'...
          [...]
        $ cd goNetViz/
        $ export GOPATH=$HOME/go
        $ go get -u github.com/google/gopacket
          [...]
        $ go build
          [...]
        $ ./goNetViz
          [...]

Or you can get it directly via [golang](https://golang.org/):

        $ go get -u github.com/florianl/goNetViz
          [...]
        $ $GOPATH/bin/goNetViz
          [...]

Examples
--------

The images below are based on the very same IP traffic. The differences are
based on the number of bits per pixel. In the first image one bit is used
per pixel. Then, in the second image, 3 bits of the payload are used per pixel.
This is followed by 9 and 12 bits per pixel and finally 24 bits per pixel.

![1 Payloadbits per Pixel](img/ping1.png)

![3 Payloadbits per Pixel](img/ping3.png)

![9 Payloadbits per Pixel](img/ping9.png)

![12 Payloadbits per Pixel](img/ping12.png)

![24 Payloadbits per Pixel](img/ping24.png)

An interactive output to the terminal could look like this:

![Interactive Terminal output](https://github.com/florianl/goNetViz/raw/master/img/terminal.gif)

