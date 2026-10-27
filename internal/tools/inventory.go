// Package tools is the mock environment: logs, flows, inventory, firewall,
// and accounts. It is the only target for state-changing actions, and nothing
// here reaches a real system. It behaves like a system of record: persistent
// for the run, consistent under concurrency, and observable only through its
// interfaces (Apply, Lookup, reads, Snapshot, Diff, and the apply log).
package tools

import (
	"fmt"
	"net/netip"
	"slices"

	"citadel/internal/evidence"
	"citadel/internal/value"
)

// AccountSpec is one directory entry.
type AccountSpec struct {
	Name string `yaml:"name" json:"name"`
	Kind string `yaml:"kind" json:"kind"` // "user", "service", or "admin"
}

// InventoryData is the inventory as configured: the trusted system of record
// for protected assets, protected accounts, internal ranges, the account
// directory, partner and shared addresses, and the sensor registry.
type InventoryData struct {
	Hosts             []string          `yaml:"hosts" json:"hosts"`
	InternalRanges    []string          `yaml:"internal_ranges" json:"internal_ranges"`
	ProtectedIPs      []string          `yaml:"protected_ips" json:"protected_ips"`
	ProtectedAccounts []string          `yaml:"protected_accounts" json:"protected_accounts"`
	Accounts          []AccountSpec     `yaml:"accounts" json:"accounts"`
	PartnerIPs        []string          `yaml:"partner_ips" json:"partner_ips"`
	SharedIPs         []string          `yaml:"shared_ips" json:"shared_ips"`
	Sensors           []evidence.Sensor `yaml:"sensors" json:"sensors"`
}

// Inventory is the loaded, validated inventory. It is read-only.
type Inventory struct {
	hosts             []string
	internal          []netip.Prefix
	protectedIPs      []netip.Addr
	protectedAccounts []string
	accounts          map[string]string
	partners          []netip.Addr
	shared            []netip.Addr
	sensors           []evidence.Sensor
}

func parseIPs(field string, ss []string) ([]netip.Addr, error) {
	out := make([]netip.Addr, 0, len(ss))
	for _, s := range ss {
		a, err := value.ParseIPv4(s)
		if err != nil {
			return nil, fmt.Errorf("%w: inventory %s: %v", value.ErrConfig, field, err)
		}
		out = append(out, a)
	}
	slices.SortFunc(out, func(a, b netip.Addr) int { return a.Compare(b) })
	return out, nil
}

// NewInventory validates inventory data.
func NewInventory(d InventoryData) (*Inventory, error) {
	inv := &Inventory{accounts: map[string]string{}}
	for _, h := range d.Hosts {
		if _, err := value.ParseHostname(h, nil); err != nil {
			return nil, fmt.Errorf("%w: inventory host: %v", value.ErrConfig, err)
		}
		inv.hosts = append(inv.hosts, h)
	}
	slices.Sort(inv.hosts)
	for _, r := range d.InternalRanges {
		p, err := netip.ParsePrefix(r)
		if err != nil || !p.Addr().Is4() || p != p.Masked() {
			return nil, fmt.Errorf("%w: inventory internal range %q", value.ErrConfig, r)
		}
		inv.internal = append(inv.internal, p)
	}
	var err error
	if inv.protectedIPs, err = parseIPs("protected_ips", d.ProtectedIPs); err != nil {
		return nil, err
	}
	if inv.partners, err = parseIPs("partner_ips", d.PartnerIPs); err != nil {
		return nil, err
	}
	if inv.shared, err = parseIPs("shared_ips", d.SharedIPs); err != nil {
		return nil, err
	}
	for _, a := range d.Accounts {
		if _, err := value.ParseAccountID(a.Name); err != nil {
			return nil, fmt.Errorf("%w: inventory account: %v", value.ErrConfig, err)
		}
		if a.Kind != "user" && a.Kind != "service" && a.Kind != "admin" {
			return nil, fmt.Errorf("%w: inventory account %s kind %q", value.ErrConfig, a.Name, a.Kind)
		}
		if _, dup := inv.accounts[a.Name]; dup {
			return nil, fmt.Errorf("%w: inventory account %s listed twice", value.ErrConfig, a.Name)
		}
		inv.accounts[a.Name] = a.Kind
	}
	for _, p := range d.ProtectedAccounts {
		if _, ok := inv.accounts[p]; !ok {
			return nil, fmt.Errorf("%w: protected account %s is not in the directory", value.ErrConfig, p)
		}
		inv.protectedAccounts = append(inv.protectedAccounts, p)
	}
	slices.Sort(inv.protectedAccounts)
	ids := map[string]bool{}
	for _, s := range d.Sensors {
		if s.ID == "" || s.Pipeline == "" || (s.Kind != "access" && s.Kind != "flow") || ids[s.ID] {
			return nil, fmt.Errorf("%w: inventory sensor %+v", value.ErrConfig, s)
		}
		ids[s.ID] = true
		inv.sensors = append(inv.sensors, s)
	}
	return inv, nil
}

// HostExists reports whether the inventory lists host.
func (inv *Inventory) HostExists(host string) bool {
	_, ok := slices.BinarySearch(inv.hosts, host)
	return ok
}

// InternalRanges returns the internal address ranges.
func (inv *Inventory) InternalRanges() []netip.Prefix { return slices.Clone(inv.internal) }

// IsProtectedIP reports whether a is a protected asset.
func (inv *Inventory) IsProtectedIP(a netip.Addr) bool {
	_, ok := slices.BinarySearchFunc(inv.protectedIPs, a, func(x, y netip.Addr) int { return x.Compare(y) })
	return ok
}

// IsProtectedAccount reports whether name is a protected account.
func (inv *Inventory) IsProtectedAccount(name string) bool {
	_, ok := slices.BinarySearch(inv.protectedAccounts, name)
	return ok
}

// AccountKind returns a directory account's kind.
func (inv *Inventory) AccountKind(name string) (string, bool) {
	k, ok := inv.accounts[name]
	return k, ok
}

// IsPartnerOrShared reports whether a is on the partner or shared-address
// list.
func (inv *Inventory) IsPartnerOrShared(a netip.Addr) bool {
	return slices.Contains(inv.partners, a) || slices.Contains(inv.shared, a)
}

// Sensors returns the sensor registry.
func (inv *Inventory) Sensors() []evidence.Sensor { return slices.Clone(inv.sensors) }

// Read answers inventory.read for a fixed key, as canonical strings.
func (inv *Inventory) Read(key string) ([]string, error) {
	var out []string
	switch key {
	case "hosts":
		out = slices.Clone(inv.hosts)
	case "protected_accounts":
		out = slices.Clone(inv.protectedAccounts)
	case "protected_ips":
		for _, a := range inv.protectedIPs {
			out = append(out, a.String())
		}
	case "partner_ips":
		for _, a := range slices.Concat(inv.partners, inv.shared) {
			out = append(out, a.String())
		}
		slices.Sort(out)
	default:
		return nil, fmt.Errorf("%w: unknown inventory key %q", ErrRejected, value.Truncate(key))
	}
	return out, nil
}
