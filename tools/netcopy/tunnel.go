package main

import (
	"fmt"
	"net"
	"time"
)

const (
	CloseTunnel = 1
)

type Tunnel struct {
	conn []net.Conn

	dch     chan []byte // data channel to transfer receiving data
	ach     chan int    // admin channel
	timeout time.Duration
	srcAddr string
}

func NewTunnel(count int, protocol string, srcAddr string, targetServerAddr string) *Tunnel {
	t := new(Tunnel)
	t.dch = make(chan []byte, 5)
	t.ach = make(chan int)
	t.timeout = time.Duration(1) * time.Second
	t.srcAddr = srcAddr

	for c := 0; c < count; c++ {
		conn, err := net.Dial("tcp", targetServerAddr)
		if err != nil {
			fmt.Printf("[%s] connect to %s failed : %v\n", protocol, targetServerAddr, err.Error())
			return nil
		}
		fmt.Printf("==========> Create Tunnel %v [%v -> %v]\n", t.srcAddr, conn.LocalAddr(), conn.RemoteAddr())
		t.conn = append(t.conn, conn)

		go t.read(conn)
		go t.serve()
	}

	return t
}

func (t *Tunnel) read(conn net.Conn) {
	buf := make([]byte, 65536)
	for {
		conn.SetReadDeadline(time.Now().Add(t.timeout))
		n, e := conn.Read(buf)
		if e != nil {
			if neterr, ok := e.(net.Error); ok {
				if n == 0 && neterr != nil && (neterr.Timeout() || neterr.Temporary()) {
					continue
				}
			}
			fmt.Printf("stop reading data. srcAddr=%v n=%d err=%v\n", t.srcAddr, n, e.Error())
			break
		}
	}
}

func (t *Tunnel) serve() {
	for {
		select {
		case data := <-t.dch:
			for _, conn := range t.conn {
				conn.Write(data)
			}
		case closing := <-t.ach:
			if closing == CloseTunnel {
				for _, conn := range t.conn {
					conn.Write([]byte(""))
					fmt.Printf("==========> Close Tunnel %v [%v -> %v]\n", t.srcAddr, conn.LocalAddr(), conn.RemoteAddr())
					conn.Close()
				}
			}
			return
		}
	}
}

func (t *Tunnel) Write(d []byte) {
	t.dch <- d
}

func (t *Tunnel) Close() {
	t.ach <- CloseTunnel
	t.timeout = time.Second
}
