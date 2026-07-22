package handler

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/labstack/echo/v4"
	"golang.zx2c4.com/wireguard/wgctrl"

	"github.com/ngoduykhanh/wireguard-ui/model"
	"github.com/ngoduykhanh/wireguard-ui/store"
)

// WGPeerVM is wireguard ctrl peer mapped for templates.
type WGPeerVM struct {
	Name              string
	Email             string
	PublicKey         string
	ReceivedBytes     int64
	TransmitBytes     int64
	LastHandshakeTime time.Time
	LastHandshakeRel  time.Duration
	Connected         bool
	AllocatedIP       string
	Endpoint          string
}

// WGDeviceVM wraps peers for one interface.
type WGDeviceVM struct {
	Name  string
	Peers []WGPeerVM
}

// ServerBannerVM summarizes kernel WireGuard presence for the Server page status stripe.
type ServerBannerVM struct {
	IfaceWant        string
	IsListening      bool // interface found in wgctrl
	UdpListenPortCfg int  // UDP port configured in WireGuard UI DB
	WgPeersTotal     int
	WgPeersRecent    int // handshake recent (≈3 min)
	WgBackendErr     string
	HostUptime       string // host uptime approximation
}

// BuildServerBannerVM matches one interface name from wgctrl device list (+ optional wgctrl error message).
func BuildServerBannerVM(ifaceWant string, devices []WGDeviceVM, wgBackendErr string, cfgListenUDP int, hostUptime string) ServerBannerVM {
	vm := ServerBannerVM{
		IfaceWant:        ifaceWant,
		UdpListenPortCfg: cfgListenUDP,
		HostUptime:       hostUptime,
	}
	if wgBackendErr != "" {
		vm.WgBackendErr = wgBackendErr
		return vm
	}
	for _, d := range devices {
		if d.Name != ifaceWant {
			continue
		}
		vm.IsListening = true
		vm.WgPeersTotal = len(d.Peers)
		for _, p := range d.Peers {
			if p.LastHandshakeRel.Minutes() < 3 {
				vm.WgPeersRecent++
			}
		}
		break
	}
	return vm
}

// GatherWireGuardStatusDevices returns peer stats from wg interfaces; errMsg holds wgctrl errors (empty if ok).
func GatherWireGuardStatusDevices(db store.IStore, c echo.Context) ([]WGDeviceVM, string, error) {
	wgClient, err := wgctrl.New()
	if err != nil {
		return nil, err.Error(), nil
	}
	defer func() { _ = wgClient.Close() }()

	devices, err := wgClient.Devices()
	if err != nil {
		return nil, err.Error(), nil
	}

	devicesVm := make([]WGDeviceVM, 0, len(devices))
	if len(devices) == 0 {
		return devicesVm, "", nil
	}

	clients, err := db.GetClients(false)
	if err != nil {
		return nil, "", fmt.Errorf("%w", err)
	}

	m := make(map[string]*model.Client)
	for i := range clients {
		if clients[i].Client != nil {
			m[clients[i].Client.PublicKey] = clients[i].Client
		}
	}

	conv := map[bool]int{true: 1, false: 0}
	for i := range devices {
		devVm := WGDeviceVM{Name: devices[i].Name}
		for j := range devices[i].Peers {
			parts := make([]string, 0, len(devices[i].Peers[j].AllowedIPs))
			for _, ip := range devices[i].Peers[j].AllowedIPs {
				parts = append(parts, ip.String())
			}
			allocatedIPs := strings.Join(parts, ", ")
			pVm := WGPeerVM{
				PublicKey:         devices[i].Peers[j].PublicKey.String(),
				ReceivedBytes:     devices[i].Peers[j].ReceiveBytes,
				TransmitBytes:     devices[i].Peers[j].TransmitBytes,
				LastHandshakeTime: devices[i].Peers[j].LastHandshakeTime,
				LastHandshakeRel:  time.Since(devices[i].Peers[j].LastHandshakeTime),
				AllocatedIP:       allocatedIPs,
			}
			pVm.Connected = pVm.LastHandshakeRel.Minutes() < 3.

			if isAdmin(c) {
				pVm.Endpoint = devices[i].Peers[j].Endpoint.String()
			}

			if _client, ok := m[pVm.PublicKey]; ok {
				pVm.Name = _client.Name
				pVm.Email = _client.Email
			}

			devVm.Peers = append(devVm.Peers, pVm)
		}
		sort.SliceStable(devVm.Peers, func(i, j int) bool { return devVm.Peers[i].Name < devVm.Peers[j].Name })
		sort.SliceStable(devVm.Peers, func(i, j int) bool { return conv[devVm.Peers[i].Connected] > conv[devVm.Peers[j].Connected] })
		devicesVm = append(devicesVm, devVm)
	}

	return devicesVm, "", nil
}

// PeerTrafficRow RX/TX for one persisted public key (wgctrl counters keyed by pubkey string).
// Connected matches dashboard logic: recent WireGuard handshake (see GatherWireGuardStatusDevices).
type PeerTrafficRow struct {
	Rx        int64 `json:"rx"`
	Tx        int64 `json:"tx"`
	Connected bool  `json:"connected"`
}

// DashboardStatsRow contains compact dynamic KPI values for dashboard polling.
type DashboardStatsRow struct {
	TotalPeers       int   `json:"total_peers"`
	EnabledPeers     int   `json:"enabled_peers"`
	OnlineSessions   int   `json:"online_sessions"`
	BytesReceived    int64 `json:"bytes_received"`
	BytesTransmitted int64 `json:"bytes_transmitted"`
}

// GetWgPeerStats returns live WG peer counters by client public_key for UI (e.g. client cards).
func GetWgPeerStats(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		return getCachedWgPeerStats(c)
	}
}

var (
	wgPeerStatsCacheMu sync.Mutex
	wgPeerStatsCacheAt time.Time
	wgPeerStatsCacheVal map[string]PeerTrafficRow
)

// getCachedWgPeerStats returns RX/TX counters per peer public key via wgctrl only (no DB),
// cached briefly to keep UI responsive.
func getCachedWgPeerStats(c echo.Context) error {
	const ttl = 5 * time.Second

	wgPeerStatsCacheMu.Lock()
	if wgPeerStatsCacheVal != nil && time.Since(wgPeerStatsCacheAt) < ttl {
		out := wgPeerStatsCacheVal
		wgPeerStatsCacheMu.Unlock()
		return c.JSON(http.StatusOK, out)
	}
	wgPeerStatsCacheMu.Unlock()

	wgClient, err := wgctrl.New()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, err.Error()})
	}
	defer func() { _ = wgClient.Close() }()

	devices, err := wgClient.Devices()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, err.Error()})
	}

	const handshakeRecent = 3 * time.Minute

	out := make(map[string]PeerTrafficRow)
	for _, dev := range devices {
		for _, peer := range dev.Peers {
			pk := peer.PublicKey.String()
			e := out[pk]
			e.Rx += peer.ReceiveBytes
			e.Tx += peer.TransmitBytes
			lh := peer.LastHandshakeTime
			rel := time.Since(lh)
			conn := !lh.IsZero() && rel < handshakeRecent
			e.Connected = e.Connected || conn
			out[pk] = e
		}
	}

	wgPeerStatsCacheMu.Lock()
	wgPeerStatsCacheVal = out
	wgPeerStatsCacheAt = time.Now()
	wgPeerStatsCacheMu.Unlock()

	return c.JSON(http.StatusOK, out)
}

// GetDashboardStats returns dynamic KPI totals for dashboard cards.
func GetDashboardStats(db store.IStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		devicesVm, _, err := GatherWireGuardStatusDevices(db, c)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, err.Error()})
		}

		stats := DashboardStatsRow{}
		onlineByPub := map[string]bool{}
		for _, dev := range devicesVm {
			for _, p := range dev.Peers {
				stats.BytesReceived += p.ReceivedBytes
				stats.BytesTransmitted += p.TransmitBytes
				if p.Connected && p.PublicKey != "" {
					onlineByPub[p.PublicKey] = true
				}
			}
		}

		clients, err := db.GetClients(false)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, jsonHTTPResponse{false, err.Error()})
		}
		stats.TotalPeers = len(clients)
		for _, cd := range clients {
			if cd.Client == nil {
				continue
			}
			if cd.Client.Enabled {
				stats.EnabledPeers++
			}
			if cd.Client.Enabled && onlineByPub[cd.Client.PublicKey] {
				stats.OnlineSessions++
			}
		}

		return c.JSON(http.StatusOK, stats)
	}
}
