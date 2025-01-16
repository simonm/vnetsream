package capture

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags "$BPF_CFLAGS" bpf ../ebpf/xdp_prog.c -- -I/usr/include/x86_64-linux-gnu -I/usr/bin/../include/bpf

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

type PacketInfo struct {
	SrcIP   net.IP
	DstIP   net.IP
	SrcPort uint16
	DstPort uint16
}

type Capturer struct {
	objs           bpfObjects
	link           link.Link
	perfReader     *perf.Reader
	packetInfoChan chan PacketInfo
}

func NewCapturer() *Capturer {
	return &Capturer{
		packetInfoChan: make(chan PacketInfo, 1000),
	}
}

func (c *Capturer) Start(interfaceName string) error {
	if err := c.loadAndAttach(interfaceName); err != nil {
		return fmt.Errorf("failed to load and attach eBPF program: %v", err)
	}

	go c.readPerfEvents()

	return nil
}

func (c *Capturer) loadAndAttach(interfaceName string) error {
	if err := loadBpfObjects(&c.objs, nil); err != nil {
		return fmt.Errorf("loading objects: %v", err)
	}

	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return fmt.Errorf("getting interface %q: %v", interfaceName, err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   c.objs.XdpProgMain,
		Interface: iface.Index,
	})
	if err != nil {
		return fmt.Errorf("attaching XDP: %v", err)
	}
	c.link = l

	rd, err := perf.NewReader(c.objs.PacketMap, 4096)
	if err != nil {
		return fmt.Errorf("creating perf event reader: %v", err)
	}
	c.perfReader = rd

	return nil
}

func (c *Capturer) readPerfEvents() {
	for {
		record, err := c.perfReader.Read()
		if err != nil {
			if err == perf.ErrClosed {
				return
			}
			log.Printf("Error reading perf event: %v", err)
			continue
		}

		if record.LostSamples != 0 {
			log.Printf("Lost %d samples", record.LostSamples)
			continue
		}

		var packetInfo PacketInfo
		packetInfo.SrcIP = net.IP(record.RawSample[:4])
		packetInfo.DstIP = net.IP(record.RawSample[4:8])
		packetInfo.SrcPort = binary.BigEndian.Uint16(record.RawSample[8:10])
		packetInfo.DstPort = binary.BigEndian.Uint16(record.RawSample[10:12])

		c.packetInfoChan <- packetInfo
	}
}

func (c *Capturer) GetPacketInfoChan() <-chan PacketInfo {
	return c.packetInfoChan
}

func (c *Capturer) Stop() error {
	if c.link != nil {
		c.link.Close()
	}
	if c.perfReader != nil {
		c.perfReader.Close()
	}
	c.objs.Close()
	close(c.packetInfoChan)
	return nil
}
