package main

import (
	"bufio"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

type channelTun struct {
	in     chan []byte
	out    chan []byte
	events chan tun.Event
	closed chan struct{}
	once   sync.Once
}

func newChannelTun() *channelTun {
	return &channelTun{
		in:     make(chan []byte, 16),
		out:    make(chan []byte, 16),
		events: make(chan tun.Event, 4),
		closed: make(chan struct{}),
	}
}

func (t *channelTun) File() *os.File { return nil }

func (t *channelTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if len(bufs) == 0 || len(sizes) == 0 {
		return 0, errors.New("empty TUN read batch")
	}
	select {
	case packet := <-t.in:
		if offset+len(packet) > len(bufs[0]) {
			return 0, io.ErrShortBuffer
		}
		copy(bufs[0][offset:], packet)
		sizes[0] = len(packet)
		return 1, nil
	case <-t.closed:
		return 0, os.ErrClosed
	}
}

func (t *channelTun) Write(bufs [][]byte, offset int) (int, error) {
	for index, buffer := range bufs {
		if offset > len(buffer) {
			return index, io.ErrShortBuffer
		}
		packet := append([]byte(nil), buffer[offset:]...)
		select {
		case t.out <- packet:
		case <-t.closed:
			return index, os.ErrClosed
		}
	}
	return len(bufs), nil
}

func (t *channelTun) MTU() (int, error)        { return 1420, nil }
func (t *channelTun) Name() (string, error)    { return "awg-interop-tun", nil }
func (t *channelTun) Events() <-chan tun.Event { return t.events }
func (t *channelTun) BatchSize() int           { return 1 }

func (t *channelTun) Close() error {
	t.once.Do(func() {
		close(t.closed)
		close(t.events)
	})
	return nil
}

func listenPort(uapi string) (string, error) {
	for _, line := range strings.Split(uapi, "\n") {
		if strings.HasPrefix(line, "listen_port=") {
			return strings.TrimPrefix(line, "listen_port="), nil
		}
	}
	return "", errors.New("listen_port missing from UAPI response")
}

func main() {
	mode := flag.String("mode", "awg30", "wireguard, awg30 or awg31")
	privateKey := flag.String("private-key", "", "local static private key in hex")
	peerPublicKey := flag.String("peer-public-key", "", "peer static public key in hex")
	endpoint := flag.String("endpoint", "", "Rust UDP endpoint")
	flag.Parse()

	if *privateKey == "" || *peerPublicKey == "" || *endpoint == "" {
		fmt.Fprintln(os.Stderr, "private-key, peer-public-key and endpoint are required")
		os.Exit(2)
	}
	if _, err := hex.DecodeString(*privateKey); err != nil {
		fmt.Fprintln(os.Stderr, "invalid private key:", err)
		os.Exit(2)
	}
	if _, err := hex.DecodeString(*peerPublicKey); err != nil {
		fmt.Fprintln(os.Stderr, "invalid peer public key:", err)
		os.Exit(2)
	}

	tunDevice := newChannelTun()
	logger := device.NewLogger(device.LogLevelSilent, "interop")
	dev := device.NewDevice(tunDevice, conn.NewStdNetBind(), logger)
	defer dev.Close()

	var uapi strings.Builder
	fmt.Fprintf(&uapi, "private_key=%s\n", *privateKey)
	if *mode != "wireguard" {
		uapi.WriteString("h1=100-200\nh2=300-400\nh3=500-600\nh4=700-800\n")
		uapi.WriteString("s1=12\ns2=12\ns3=12\ns4=12\n")
		uapi.WriteString("header_protection_key=" + strings.Repeat("66", 32) + "\n")
	}
	if *mode == "awg31" {
		uapi.WriteString("random_trailers=true\n")
		uapi.WriteString("content_padding_addition=1-4\n")
		uapi.WriteString("disable_cookies=false\n")
	}
	uapi.WriteString("replace_peers=true\n")
	fmt.Fprintf(&uapi, "public_key=%s\nallowed_ip=10.0.0.0/24\nendpoint=%s\n", *peerPublicKey, *endpoint)

	if err := dev.IpcSet(uapi.String()); err != nil {
		fmt.Fprintln(os.Stderr, "IpcSet:", err)
		os.Exit(1)
	}
	if err := dev.Up(); err != nil {
		fmt.Fprintln(os.Stderr, "Device.Up:", err)
		os.Exit(1)
	}
	tunDevice.events <- tun.EventUp

	state, err := dev.IpcGet()
	if err != nil {
		fmt.Fprintln(os.Stderr, "IpcGet:", err)
		os.Exit(1)
	}
	port, err := listenPort(state)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("PORT=%s\n", port)

	go func() {
		for {
			select {
			case packet := <-tunDevice.out:
				fmt.Printf("TUN:%x\n", packet)
			case <-tunDevice.closed:
				return
			}
		}
	}()

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "QUIT" {
			return
		}
		if strings.HasPrefix(line, "SEND:") {
			packet, err := hex.DecodeString(strings.TrimPrefix(line, "SEND:"))
			if err != nil {
				fmt.Fprintln(os.Stderr, "invalid SEND packet:", err)
				continue
			}
			select {
			case tunDevice.in <- packet:
			case <-tunDevice.closed:
				return
			}
		}
	}
}
