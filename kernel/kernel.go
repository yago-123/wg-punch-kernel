package kernel

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/go-logr/logr"

	"github.com/vishvananda/netlink"
	"github.com/yago-123/wg-punch/pkg/peer"
	"github.com/yago-123/wg-punch/pkg/tunnel"
	tunnelUtil "github.com/yago-123/wg-punch/pkg/tunnel/util"
	util "github.com/yago-123/wg-punch/pkg/util"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	WireGuardLinkType   = "wireguard"
	HandshakeTriggerMsg = "hello wg"

	HandshakeTriggerLoopInterval = 300 * time.Millisecond
	HandshakeCheckInterval       = 500 * time.Second
)

type kernelWGTunnel struct {
	listener *net.UDPConn
	privKey  wgtypes.Key

	config *tunnel.Config
	logger logr.Logger
}

func NewTunnel(cfg *tunnel.Config, logger logr.Logger) (tunnel.Tunnel, error) {
	// todo(): validate config

	privKey, err := wgtypes.ParseKey(cfg.PrivKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return &kernelWGTunnel{
		privKey: privKey,
		config:  cfg,
		logger:  logger,
	}, nil
}

func (kwgt *kernelWGTunnel) Start(ctx context.Context, conn *net.UDPConn, remotePeer peer.Info, cancelPunch context.CancelFunc) error {
	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("failed to open wgctrl rendclient: %w", err)
	}
	defer client.Close()

	remotePubKey, err := wgtypes.ParseKey(remotePeer.PublicKey)
	if err != nil {
		return fmt.Errorf("invalid remote public key: %w", err)
	}

	cfg := wgtypes.Config{
		PrivateKey:   &kwgt.privKey,
		ListenPort:   &kwgt.config.ListenPort,
		ReplacePeers: kwgt.config.ReplacePeer,
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey:                   remotePubKey,
				Endpoint:                    remotePeer.Endpoint,
				AllowedIPs:                  remotePeer.AllowedIPs,
				PersistentKeepaliveInterval: &kwgt.config.KeepAliveInterval,
			},
		},
	}

	kwgt.logger.Info("configuring WireGuard device", "iface", kwgt.config.Iface)

	if err = kwgt.ensureInterfaceExists(kwgt.config.Iface); err != nil {
		return fmt.Errorf("failed to ensure interface exists: %w", err)
	}

	if err = tunnelUtil.AssignAddressToIface(kwgt.config.Iface, kwgt.config.IfaceIPv4CIDR); err != nil {
		return fmt.Errorf("failed to assign address to interface: %w", err)
	}

	if err = tunnelUtil.AddPeerRoutes(kwgt.config.Iface, remotePeer.AllowedIPs); err != nil {
		return fmt.Errorf("failed to add remotePeer routes: %w", err)
	}

	// Cancel the punching process so that it doesn't interfere with the connection
	cancelPunch()

	// Release the UDP connection so that WireGuard can take over. Check if nil just in case, by default the conn passed
	// should be a valid one
	if conn != nil {
		// Stop UDP connection so that WireGuard can take over
		if errConnUDP := conn.Close(); errConnUDP != nil {
			return fmt.Errorf("failed to close UDP connection: %w", errConnUDP)
		}
	}

	if errDevice := client.ConfigureDevice(kwgt.config.Iface, cfg); errDevice != nil {
		return fmt.Errorf("failed to configure device: %w", errDevice)
	}

	// In order to ensure that the handshake is triggered, we start a loop that sends a message to the remote peer
	// at regular intervals. This is necessary because the WireGuard kernel module does not automatically trigger
	// handshakes. Once the handshake has been established, it must be canceled
	ctxHandshakeTrigger, cancelHandshakeTrigger := context.WithCancel(ctx)
	defer cancelHandshakeTrigger()

	kwgt.logger.Info("starting handshake trigger")

	go kwgt.startHandshakeTriggerLoop(ctxHandshakeTrigger, remotePeer.Endpoint, HandshakeTriggerLoopInterval)

	kwgt.logger.Info("waiting for handshake")

	// todo(): pass cancelHandshakeTrigger to the loop once we verified is really 100% needed
	if errHandshake := kwgt.waitForHandshake(ctx, client, remotePubKey, HandshakeCheckInterval); errHandshake != nil {
		return fmt.Errorf("failed to wait for handshake: %w", errHandshake)
	}

	kwgt.listener = conn
	return nil
}

func (kwgt *kernelWGTunnel) ListenPort() int {
	return kwgt.config.ListenPort
}

func (kwgt *kernelWGTunnel) PublicKey() string {
	return kwgt.privKey.PublicKey().String()
}

func (kwgt *kernelWGTunnel) Stop(_ context.Context) error {
	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("failed to open wgctrl rendclient: %w", err)
	}
	defer client.Close()

	// Clear all peers first
	if errConf := client.ConfigureDevice(kwgt.config.Iface, wgtypes.Config{
		ReplacePeers: true,
		Peers:        []wgtypes.PeerConfig{},
	}); errConf != nil {
		return fmt.Errorf("failed to clear WireGuard config: %w", errConf)
	}

	// Delete the interface
	link, err := netlink.LinkByName(kwgt.config.Iface)
	if err != nil {
		return fmt.Errorf("failed to get link %s: %w", kwgt.config.Iface, err)
	}

	if errLink := netlink.LinkDel(link); errLink != nil {
		return fmt.Errorf("failed to delete link %s: %w", kwgt.config.Iface, errLink)
	}

	return nil
}

// ensureInterfaceExists checks if the WireGuard interface exists and creates it if not
func (kwgt *kernelWGTunnel) ensureInterfaceExists(iface string) error {
	if !kwgt.config.CreateIface {
		return nil
	}

	// Check if the interface already exists
	_, err := netlink.LinkByName(iface)
	if err == nil {
		return nil
	}

	// Only proceed if the interface is truly missing
	// todo(): improve error handling
	if !strings.Contains(err.Error(), "Link not found") {
		return fmt.Errorf("error checking interface %q: %w", iface, err)
	}

	link := &netlink.GenericLink{
		LinkAttrs: netlink.LinkAttrs{Name: iface},
		LinkType:  WireGuardLinkType,
	}

	// Create the WireGuard interface
	if err = netlink.LinkAdd(link); err != nil {
		return fmt.Errorf("failed to create WireGuard interface %q: %w", iface, err)
	}

	// Bring the interface up
	if err = netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to bring up interface %q: %w", iface, err)
	}

	return nil
}

// waitForHandshake waits for the handshake with the remote peer to be established
func (kwgt *kernelWGTunnel) waitForHandshake(ctx context.Context, wgClient *wgctrl.Client, remotePubKey wgtypes.Key, interval time.Duration) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("context cancelled or deadline exceeded while waiting for handshake with peer %s: %w", remotePubKey, ctx.Err())

		case <-ticker.C:
			// Check if the device exists
			device, errDevice := wgClient.Device(kwgt.config.Iface)
			if errDevice != nil {
				return fmt.Errorf("failed to get device info: %w", errDevice)
			}

			// Check if the peer is present in the device
			if hasHandshake(device, remotePubKey) {
				return nil
			}
		}
	}
}

// hasHandshake checks if the peer has a handshake with the given public key
func hasHandshake(device *wgtypes.Device, remotePubKey wgtypes.Key) bool {
	for _, peer := range device.Peers {
		if peer.PublicKey == remotePubKey && !peer.LastHandshakeTime.IsZero() {
			return true
		}
	}
	return false
}

// todo(): remove
func (kwgt *kernelWGTunnel) startHandshakeTriggerLoop(ctx context.Context, endpoint *net.UDPAddr, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			conn, err := net.DialUDP(util.UDPProtocol, nil, endpoint)
			if err != nil {
				kwgt.logger.Error(err, "Error dialing UDP", "endpoint", endpoint.String())
				continue
			}

			_, err = conn.Write([]byte(HandshakeTriggerMsg))
			conn.Close()
			if err != nil {
				kwgt.logger.Error(err, "Error writing handshake message", "endpoint", endpoint.String())
			}
		}
	}
}
