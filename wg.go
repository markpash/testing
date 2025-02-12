package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/markpash/testing/wireguard/conn"
	"github.com/markpash/testing/wireguard/device"
	wgtun "github.com/markpash/testing/wireguard/tun"
	"github.com/markpash/testing/wireguard/tun/netstack"
	"github.com/markpash/testing/wiresocks"
)

func usermodeTunTest(ctx context.Context, tnet *netstack.Net, url string) error {
	ctx, cancel := context.WithDeadline(ctx, time.Now().Add(5*time.Second))
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("connection test failed: %w", ctx.Err())
		default:
		}

		client := http.Client{Transport: &http.Transport{
			DialContext:           tnet.DialContext,
			ResponseHeaderTimeout: 5 * time.Second,
		}}
		resp, err := client.Head(url)
		if err != nil || resp.StatusCode != http.StatusOK {
			continue
		}

		break
	}

	return nil
}

func waitHandshake(ctx context.Context, l *slog.Logger, dev *device.Device) error {
	lastHandshakeSecs := "0"
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		get, err := dev.IpcGet()
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(strings.NewReader(get))
		for scanner.Scan() {
			line := scanner.Text()
			if line == "" {
				break
			}

			key, value, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}

			if key == "last_handshake_time_sec" {
				lastHandshakeSecs = value
				break
			}
		}
		if lastHandshakeSecs != "0" {
			l.Debug("handshake complete")
			break
		}

		l.Debug("waiting on handshake")
		time.Sleep(250 * time.Millisecond)
	}

	return nil
}

func establishWireguard(l *slog.Logger, conf *wiresocks.Configuration, tunDev wgtun.Device, t string) (*device.Device, error) {
	// create the IPC message to establish the wireguard conn
	var request bytes.Buffer

	request.WriteString(fmt.Sprintf("private_key=%s\n", conf.Interface.PrivateKey))

	for _, peer := range conf.Peers {
		request.WriteString(fmt.Sprintf("public_key=%s\n", peer.PublicKey))
		request.WriteString(fmt.Sprintf("persistent_keepalive_interval=%d\n", peer.KeepAlive))
		request.WriteString(fmt.Sprintf("preshared_key=%s\n", peer.PreSharedKey))
		request.WriteString(fmt.Sprintf("endpoint=%s\n", peer.Endpoint))
		request.WriteString(fmt.Sprintf("trick=%s\n", t))
		request.WriteString(fmt.Sprintf("reserved=%d,%d,%d\n", peer.Reserved[0], peer.Reserved[1], peer.Reserved[2]))

		for _, cidr := range peer.AllowedIPs {
			request.WriteString(fmt.Sprintf("allowed_ip=%s\n", cidr))
		}
	}

	var err error
	dev := device.NewDevice(
		tunDev,
		conn.NewDefaultBind(),
		device.NewSLogger(l.With("subsystem", "wireguard-go")),
	)
	defer func() {
		if err != nil {
			dev.BindClose()
			dev.Close()
		}
	}()

	err = dev.IpcSet(request.String())
	if err != nil {
		return nil, err
	}

	err = dev.Up()
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(10*time.Second))
	defer cancel()

	err = waitHandshake(ctx, l, dev)
	if err != nil {
		return nil, err
	}

	return dev, nil
}
