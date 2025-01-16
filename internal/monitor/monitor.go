package monitor

import (
    "encoding/binary"
    "fmt"
    "log"
    
    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/perf"
)

type TLSMonitor struct {
    objs      *bpfObjects
    link      link.Link
    perfReader *perf.Reader
    eventChan chan TLSEvent
}

type TLSEvent struct {
    ContentType   uint8
    Version       uint16
    HandshakeType uint8
    IsClientHello bool
    IsServerHello bool
    IsCertificate bool
    Data          []byte
}

func NewMonitor() (*TLSMonitor, error) {
    m := &TLSMonitor{
        eventChan: make(chan TLSEvent, 1000),
    }
    
    spec, err := loadBpfObjects()
    if err != nil {
        return nil, fmt.Errorf("loading objects: %v", err)
    }
    m.objs = spec
    
    return m, nil
}

func (m *TLSMonitor) Start(interfaceName string) error {
    // Attach XDP program
    l, err := link.AttachXDP(link.XDPOptions{
        Program:   m.objs.TlsMonitor,
        Interface: interfaceName,
    })
    if err != nil {
        return fmt.Errorf("attaching XDP: %v", err)
    }
    m.link = l

    // Create perf reader
    rd, err := perf.NewReader(m.objs.Events, 4096)
    if err != nil {
        m.link.Close()
        return fmt.Errorf("creating perf reader: %v", err)
    }
    m.perfReader = rd

    // Start event processing
    go m.processEvents()

    return nil
}

func (m *TLSMonitor) processEvents() {
    for {
        record, err := m.perfReader.Read()
        if err != nil {
            if err == perf.ErrClosed {
                return
            }
            log.Printf("error reading perf event: %v", err)
            continue
        }

        if record.LostSamples != 0 {
            log.Printf("lost %d samples", record.LostSamples)
            continue
        }

        var event TLSEvent
        // Parse event data from record.RawSample
        // Send to channel
        m.eventChan <- event
    }
}

func (m *TLSMonitor) Events() <-chan TLSEvent {
    return m.eventChan
}

func (m *TLSMonitor) Close() error {
    if m.link != nil {
        m.link.Close()
    }
    if m.perfReader != nil {
        m.perfReader.Close()
    }
    if m.objs != nil {
        m.objs.Close()
    }
    close(m.eventChan)
    return nil
}
