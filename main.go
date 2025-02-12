package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"path"
	"runtime"
	"time"

	"github.com/adrg/xdg"
	"github.com/carlmjohnson/versioninfo"
	"github.com/markpash/testing/iputils"
	"github.com/markpash/testing/warp"
	"github.com/markpash/testing/wireguard/tun/netstack"
	"github.com/markpash/testing/wiresocks"
)

const singleMTU = 1330
const testURL = "http://connectivity.cloudflareclient.com/cdn-cgi/trace"

var dnsAddr = netip.MustParseAddr("1.1.1.1")

var version string = ""

func main() {
	cacheDir := ""
	switch {
	case xdg.CacheHome != "":
		cacheDir = path.Join(xdg.CacheHome, "warp-plus")
	case os.Getenv("HOME") != "":
		cacheDir = path.Join(os.Getenv("HOME"), ".cache", "warp-plus")
	default:
		cacheDir = "warp_plus_cache"
	}

	l := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	// Print ASN information
	asn, ispName, err := getASNInfo()
	if err != nil {
		fatal(l, err)
	}

	if version == "" {
		version = versioninfo.Short()
	}

	l.Info("test information", "version", version, "asn", asn, "isp", ispName, "os", runtime.GOOS)

	// Load and validate warp identity.
	ident, err := warp.LoadOrCreateIdentity(l, path.Join(cacheDir, "primary"), "")
	if err != nil {
		fatal(l, fmt.Errorf("couldn't load primary warp identity"))
	}

	identTest, err := warp.GetSourceDevice(ident.Token, ident.ID)
	if err != nil || !identTest.Enabled {
		fatal(l, fmt.Errorf("couldn't test identity"))
	}

	// Pick a random warp port to use for all of the tests.
	randPort := warp.RandomWarpPort()

	// Iterate over all warp prefixes and then run a series of tests on
	// all of the ones that are v4.
	for _, t := range []string{"t1", "t2"} {
		l := l.With("t", t)
		for _, prefix := range warp.WarpPrefixes() {
			if !prefix.Addr().Is4() {
				continue
			}

			for range 5 {
				randIP, err := iputils.RandomIPFromPrefix(prefix)
				if err != nil {
					fatal(l, fmt.Errorf("couldn't generate random IP from prefix"))
				}

				addrPort := netip.AddrPortFrom(randIP, randPort).String()

				t0 := time.Now()
				if err := testWarpAddress(l, ident, addrPort, t); err != nil {
					l.Error("warp address test failed", "duration", time.Since(t0), "prefix", prefix, "address", addrPort, "error", err)
				} else {
					l.Info("warp address test succeeded", "duration", time.Since(t0), "prefix", prefix, "address", addrPort)
				}
			}
		}
	}
	l.Info("all tests completed")
}

func testWarpAddress(l *slog.Logger, ident *warp.Identity, addrPort, t string) error {
	conf := generateWireguardConfig(ident)

	// Set up MTU
	conf.Interface.MTU = singleMTU
	// Set up DNS Address
	conf.Interface.DNS = []netip.Addr{dnsAddr}

	// Enable trick and keepalive on all peers in config
	for i, peer := range conf.Peers {
		peer.Endpoint = addrPort
		peer.Trick = true
		peer.KeepAlive = 5
		conf.Peers[i] = peer
	}

	tunDev, tnet, err := netstack.CreateNetTUN(conf.Interface.Addresses, conf.Interface.DNS, conf.Interface.MTU)
	if err != nil {
		return fmt.Errorf("couldn't create TUN device")
	}

	dev, err := establishWireguard(l, &conf, tunDev, t)
	if err != nil {
		return fmt.Errorf("couldn't establish wireguard connection")
	}
	defer dev.Close()

	// Test wireguard connectivity
	if err := usermodeTunTest(context.Background(), tnet, testURL); err != nil {
		return fmt.Errorf("couldn't test wireguard connectivity")
	}

	return nil
}

func generateWireguardConfig(i *warp.Identity) wiresocks.Configuration {
	priv, _ := wiresocks.EncodeBase64ToHex(i.PrivateKey)
	pub, _ := wiresocks.EncodeBase64ToHex(i.Config.Peers[0].PublicKey)
	clientID, _ := base64.StdEncoding.DecodeString(i.Config.ClientID)
	return wiresocks.Configuration{
		Interface: &wiresocks.InterfaceConfig{
			PrivateKey: priv,
			Addresses: []netip.Addr{
				netip.MustParseAddr(i.Config.Interface.Addresses.V4),
				netip.MustParseAddr(i.Config.Interface.Addresses.V6),
			},
		},
		Peers: []wiresocks.PeerConfig{{
			PublicKey:    pub,
			PreSharedKey: "0000000000000000000000000000000000000000000000000000000000000000",
			AllowedIPs: []netip.Prefix{
				netip.MustParsePrefix("0.0.0.0/0"),
				netip.MustParsePrefix("::/0"),
			},
			Endpoint: i.Config.Peers[0].Endpoint.Host,
			Reserved: [3]byte{clientID[0], clientID[1], clientID[2]},
		}},
	}
}

func getASNInfo() (string, string, error) {
	resp, err := http.Get("https://ifconfig.co/json")
	if err != nil {
		return "", "", fmt.Errorf("failed to get ASN info: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", fmt.Errorf("failed to read response body: %w", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", "", fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	asn, ok := result["asn"].(string)
	if !ok {
		return "", "", fmt.Errorf("invalid response format: missing 'asn' field")
	}

	ispName, ok := result["asn_org"].(string)
	if !ok {
		return "", "", fmt.Errorf("invalid response format: missing 'asn_org' field")
	}

	return asn, ispName, nil
}

func fatal(l *slog.Logger, err error) {
	l.Error(err.Error())
	os.Exit(1)
}
