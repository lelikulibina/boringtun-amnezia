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

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
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
func (t *channelTun) Name() (string, error)    { return "wireguard-interop-tun", nil }
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
	flag.String("mode", "wireguard-go", "helper mode")
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
	logger := device.NewLogger(device.LogLevelSilent, "wireguard-interop")
	dev := device.NewDevice(tunDevice, conn.NewStdNetBind(), logger)
	defer dev.Close()

	var uapi strings.Builder
	fmt.Fprintf(&uapi, "private_key=%s\n", *privateKey)
	uapi.WriteString("replace_peers=true\n")
	fmt.Fprintf(
		&uapi,
		"public_key=%s\nallowed_ip=10.0.0.0/24\nendpoint=%s\n",
		*peerPublicKey,
		*endpoint,
	)
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
	fmt.Println("READY=1")

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
