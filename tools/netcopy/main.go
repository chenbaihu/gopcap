package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strconv"

	"encoding/base64"
	"github.com/akrennmair/gopcap"
)

const (
	TYPE_IP  = 0x0800
	TYPE_ARP = 0x0806
	TYPE_IP6 = 0x86DD

	IP_ICMP = 1
	IP_INIP = 4
	IP_TCP  = 6
	IP_UDP  = 17
)

var out *bufio.Writer
var errout *bufio.Writer

func main() {

	var device *string = flag.String("i", "", "interface")
	var snaplen *int = flag.Int("s", 65535, "snaplen")
	var hexdump *bool = flag.Bool("X", false, "hexdump")
	var targetTcpServerAddress *string = flag.String("T", "", "The address of the target tcp server, for example: 192.168.0.99:80")
	var amplification *int = flag.Int("a", 1, "The amplification count")
	//var tcpTarget *string = flag.String("U", "", "The address of the target udp server, for exsample: 192.168.0.111:53")
	expr := ""

	out = bufio.NewWriter(os.Stdout)
	errout = bufio.NewWriter(os.Stderr)

	flag.Usage = func() {
		fmt.Fprintf(errout, "usage: %s [ -i interface ] [ -s snaplen ] [ -X ] [ expression ]\n", os.Args[0])
		errout.Flush()
		os.Exit(1)
	}

	flag.Parse()

	if len(flag.Args()) > 0 {
		expr = flag.Arg(0)
	}

	if *device == "" {
		devs, err := pcap.Findalldevs()
		if err != nil {
			fmt.Fprintf(errout, "tcpdump: couldn't find any devices: %s\n", err)
		}
		if 0 == len(devs) {
			flag.Usage()
		}
		*device = devs[0].Name
		for _, d := range devs {
			fmt.Printf("tcpdump: find device: [%s] [%s] [%s] %s\n", base64.StdEncoding.EncodeToString([]byte(d.Name)), d.Addresses[0].IP.String(), d.Name, d.Description)
		}
	}

	//*device = "\\Device\\NPF_{6605ECDE-64C1-4EC5-9620-1F9F3C2710E4}" // Cisco AnyConnect VPN Virtual Miniport Adapter for Windows x64
	//*device = "\\Device\\NPF_{2C972895-AB1E-40A4-88C9-E22DC2099B70}" // home wireless wifi

	fmt.Printf("tcpdump: use devices: %s\n", *device)

	h, err := pcap.Openlive(*device, int32(*snaplen), true, 0)
	if h == nil {
		fmt.Fprintf(errout, "tcpdump: %s\n", err)
		errout.Flush()
		return
	}
	defer h.Close()

	if expr != "" {
		ferr := h.Setfilter(expr)
		if ferr != nil {
			fmt.Fprintf(out, "tcpdump: %s\n", ferr)
			out.Flush()
		}
	}
	fmt.Printf("tcpdump: SetFilter [%s]\n", expr)

	fmt.Printf("tcpdump: begin to capture ... \n")

	var tunnels map[string]*Tunnel
	for pkt := h.Next(); pkt != nil; pkt = h.Next() {
		pkt.Decode()
		fmt.Fprintf(out, "%s\n", pkt.String())
		if *hexdump {
			Hexdump(pkt)
		}
		out.Flush()
		if pkt.Type == TYPE_IP || pkt.Type == TYPE_IP6 {
			srcAddr := pkt.IP.SrcAddr() + ":" + strconv.Itoa(int(pkt.TCP.SrcPort))
			if pkt.IP.Protocol == IP_TCP {
				if pkt.TCP.IsSyn() {
					fmt.Printf("==========> Got a SYN package, connecting to %s\n", *targetTcpServerAddress)
					tunnel := NewTunnel(*amplification, "tcp", *targetTcpServerAddress)
					tunnels[srcAddr] = tunnel
				} else if pkt.TCP.IsReset() || pkt.TCP.IsFin() {
					fmt.Printf("==========> Got a RESET/FIN package, close the connection\n")
					if t, ok := tunnels[srcAddr]; ok && t != nil {
						t.Close()
					}
					continue
				}

				if len(pkt.Payload) > 0 {
					fmt.Printf("==========> Got a data package, copy data to target server. len(payload)=%v\n", len(pkt.Payload))
					if t, ok := tunnels[srcAddr]; ok && t != nil {
						t.Write(pkt.Payload)
					}
				}
			} else if pkt.IP.Protocol == IP_UDP {

			}
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func Hexdump(pkt *pcap.Packet) {
	for i := 0; i < len(pkt.Data); i += 16 {
		Dumpline(uint32(i), pkt.Data[i:min(i+16, len(pkt.Data))])
	}
}

func Dumpline(addr uint32, line []byte) {
	fmt.Fprintf(out, "\t0x%04x: ", int32(addr))
	var i uint16
	for i = 0; i < 16 && i < uint16(len(line)); i++ {
		if i%2 == 0 {
			out.WriteString(" ")
		}
		fmt.Fprintf(out, "%02x", line[i])
	}
	for j := i; j <= 16; j++ {
		if j%2 == 0 {
			out.WriteString(" ")
		}
		out.WriteString("  ")
	}
	out.WriteString("  ")
	for i = 0; i < 16 && i < uint16(len(line)); i++ {
		if line[i] >= 32 && line[i] <= 126 {
			fmt.Fprintf(out, "%c", line[i])
		} else {
			out.WriteString(".")
		}
	}
	out.WriteString("\n")
}
