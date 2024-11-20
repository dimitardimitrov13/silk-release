package lib

import (
	"fmt"
	"net"
	"os"

	"code.cloudfoundry.org/lager/v3"

	"github.com/containernetworking/cni/pkg/types"
	"github.com/vishvananda/netlink"
)

// LinkOperations exposes mid-level link setup operations.
// They encapsulate low-level netlink and sysctl commands.
type LinkOperations struct {
	SysctlAdapter  sysctlAdapter
	NetlinkAdapter netlinkAdapter
	Logger         lager.Logger
}

func (s *LinkOperations) DisableIPv6(deviceName string) error {
	_, err := s.SysctlAdapter.Sysctl(fmt.Sprintf("net.ipv6.conf.%s.disable_ipv6", deviceName), "1")
	if err != nil {
		return fmt.Errorf("sysctl for %s: %s", deviceName, err)
	}
	return nil
}

func (s *LinkOperations) EnableIPv6(deviceName string) error {
	_, err := s.SysctlAdapter.Sysctl(fmt.Sprintf("net.ipv6.conf.%s.disable_ipv6", deviceName), "0")
	if err != nil {
		return fmt.Errorf("sysctl for IPv6 %s: %s", deviceName, err)
	}

	return nil
}

func (s *LinkOperations) EnableReversePathFiltering(deviceName string) error {
	_, err := s.SysctlAdapter.Sysctl(fmt.Sprintf("net.ipv4.conf.%s.rp_filter", deviceName), "1")
	if err != nil {
		return fmt.Errorf("sysctl for %s: %s", deviceName, err)
	}
	return nil
}

func (s *LinkOperations) EnableIPv4Forwarding() error {
	_, err := s.SysctlAdapter.Sysctl("net.ipv4.ip_forward", "1")
	if err != nil {
		return fmt.Errorf("enabling IPv4 forwarding: %s", err)
	}
	return nil
}

func (s *LinkOperations) EnableIPv6Forwarding() error {
	_, err := s.SysctlAdapter.Sysctl("net.ipv6.conf.eth0.forwarding", "1")
	if err != nil {
		return fmt.Errorf("enabling IPv6 forwarding: %s", err)
	}
	return nil
}

// StaticNeighborNoARP disables ARP on the link and installs a single permanent neighbor rule
// that resolves the given destIP to the given hardware address
func (s *LinkOperations) StaticNeighborNoARP(link netlink.Link, destIP net.IP, hwAddr net.HardwareAddr) error {
	err := s.NetlinkAdapter.LinkSetARPOff(link)
	if err != nil {
		return fmt.Errorf("set ARP off: %s", err)
	}

	err = s.NetlinkAdapter.NeighAddPermanentIPv4(link.Attrs().Index, destIP, hwAddr)
	if err != nil {
		return fmt.Errorf("neigh add: %s", err)
	}

	return nil
}

func (s *LinkOperations) StaticNeighborIPv6(link netlink.Link, destIP net.IP, hwAddr net.HardwareAddr) error {
	err := s.NetlinkAdapter.NeighAddPermanentIPv6(link.Attrs().Index, destIP, hwAddr)
	if err != nil {
		return fmt.Errorf("neigh add: %s", err)
	}

	return nil
}

func (s *LinkOperations) SetPointToPointAddress(link netlink.Link, localIPAddr, peerIPAddr net.IP) error {
	var mask []byte
	if localIPAddr.To4() != nil {
		// IPv4 point-to-point address configuration
		mask = []byte{255, 255, 255, 255}
	} else {
		// IPv6 point-to-point address configuration
		mask = net.CIDRMask(128, 128)
	}

	localAddr := &net.IPNet{
		IP:   localIPAddr,
		Mask: mask,
	}

	peerAddr := &net.IPNet{
		IP:   peerIPAddr,
		Mask: mask,
	}

	addr, err := s.NetlinkAdapter.ParseAddr(localAddr.String())
	if err != nil {
		return fmt.Errorf("parsing address %s: %w", localAddr, err)
	}

	addr.Peer = peerAddr

	err = s.NetlinkAdapter.AddrAddScopeLink(link, addr)
	if err != nil {
		return fmt.Errorf("adding IP address %s: %w", localAddr, err)
	}

	return nil
}

func (s *LinkOperations) RenameLink(oldName, newName string) error {
	link, err := s.NetlinkAdapter.LinkByName(oldName)
	if err != nil {
		return fmt.Errorf("failed to find link %q: %s", oldName, err)
	}

	err = s.NetlinkAdapter.LinkSetName(link, newName)
	if err != nil {
		return fmt.Errorf("set link name: %s", err)
	}

	return nil
}

func (s *LinkOperations) DeleteLinkByName(deviceName string) error {
	link, err := s.NetlinkAdapter.LinkByName(deviceName)
	if err != nil {
		s.Logger.Info("DeleteLinkByName", lager.Data{
			"deviceName": deviceName,
			"message":    err.Error(),
		})

		return nil
	}

	return s.NetlinkAdapter.LinkDel(link)
}

func (s *LinkOperations) RouteAddAll(routes []*types.Route, sourceIP net.IP) error {
	for _, r := range routes {
		dst := r.Dst
		err := s.NetlinkAdapter.RouteAdd(&netlink.Route{
			Src: sourceIP,
			Dst: &dst,
			Gw:  r.GW,
		})

		if err != nil {
			return fmt.Errorf("adding route: %s, srcIP: %s, dstIP: %s, GW: %s", err, sourceIP, dst, r.GW)
		}
	}
	return nil
}

func (s *LinkOperations) Route6AddAll(routes []*types.Route, deviceName string) error {
	link, err := s.NetlinkAdapter.LinkByName(deviceName)
	if err != nil {
		return fmt.Errorf("failed to get IPv6 interface %s: %v\n", deviceName, err)
	}

	for _, r := range routes {
		err = s.NetlinkAdapter.RouteAdd(
			&netlink.Route{Gw: r.GW, LinkIndex: link.Attrs().Index, Dst: nil, Scope: netlink.SCOPE_UNIVERSE},
		)

		if err != nil {
			return fmt.Errorf("IPv6 adding route: %s, GW: %s", err, r.GW)
		}
	}
	return nil
}

func (s *LinkOperations) SysctlIPv6Security(deviceName string) error {
	ipv6settings := map[string]string{
		"accept_ra":            "0",
		"accept_ra_defrtr":     "0",
		"accept_ra_from_local": "0",
		"accept_redirects":     "0",
		"accept_source_route":  "0",
		"accept_dad":           "0",
		"enhanced_dad":         "0",
		"suppress_frag_ndisc":  "1",
		"autoconf":             "0",
	}

	if _, err := os.Stat(fmt.Sprintf("/proc/sys/net/ipv6/conf/%s", deviceName)); os.IsNotExist(err) {
		return fmt.Errorf("device %s does not exist", deviceName)
	}

	var errs []error
	for k, v := range ipv6settings {
		_, err := s.SysctlAdapter.Sysctl(fmt.Sprintf("net.ipv6.conf.%s.%s", deviceName, k), v)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to set net.ipv6.conf.%s.%s: %w", deviceName, k, err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors occurred during sysctl configuration: %v", errs)
	}

	return nil
}
