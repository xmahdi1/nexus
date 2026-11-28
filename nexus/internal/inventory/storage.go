package inventory

import (
	"errors"
	"net/netip"
	"path"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	blockDevicesCommand = "LC_ALL=C lsblk --json --bytes --list --output KNAME,TYPE,MAJ:MIN,SIZE,RO"
	mountsCommand       = "LC_ALL=C findmnt --kernel --json --list --output TARGET,FSTYPE,MAJ:MIN"
	resolversCommand    = `LC_ALL=C awk '$1 == "nameserver" {if (NF < 2) exit 1; print $2}' /etc/resolv.conf`
	blockDevicesSource  = "lsblk"
	mountsSource        = "findmnt"
	resolversSource     = "resolv.conf"
	maxBlockDevices     = 2048
	maxMounts           = 4096
	maxResolvers        = 32
)

var deviceNumber = regexp.MustCompile(`^[0-9]{1,10}:[0-9]{1,10}$`)
var kernelDevice = regexp.MustCompile(`^[A-Za-z0-9_.!:-]{1,128}$`)
var filesystemType = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,64}$`)
var errStorage = errors.New("invalid storage observation")

type BlockDevice struct {
	Name         string `json:"name"`
	Type         string `json:"type"`
	DeviceNumber string `json:"deviceNumber"`
	SizeBytes    int64  `json:"sizeBytes"`
	ReadOnly     bool   `json:"readOnly"`
}

type Mount struct {
	Target         string `json:"target"`
	FilesystemType string `json:"filesystemType"`
	DeviceNumber   string `json:"deviceNumber"`
}

func (m Mount) key() string { return m.DeviceNumber + " " + m.FilesystemType + " " + m.Target }

type Resolver struct {
	Address  string `json:"address"`
	Priority int    `json:"priority"`
}

type blockDeviceRow struct {
	ResourceID string `gorm:"primaryKey"`
	BlockDevice
}

func (blockDeviceRow) TableName() string { return "inventory_block_devices" }

type mountRow struct {
	ResourceID string `gorm:"primaryKey"`
	Mount
}

func (mountRow) TableName() string { return "inventory_mounts" }

type resolverRow struct {
	ResourceID string `gorm:"primaryKey"`
	Resolver
}

func (resolverRow) TableName() string { return "inventory_resolvers" }

func parseBlockDevices(raw string) ([]BlockDevice, error) {
	var payload struct {
		Devices []struct {
			Name         string `json:"kname"`
			Type         string `json:"type"`
			DeviceNumber string `json:"maj:min"`
			SizeBytes    *int64 `json:"size"`
			ReadOnly     *bool  `json:"ro"`
		} `json:"blockdevices"`
	}
	if !decodeInventoryJSON(raw, &payload) || payload.Devices == nil || len(payload.Devices) > maxBlockDevices {
		return nil, errStorage
	}
	devices := make([]BlockDevice, 0, len(payload.Devices))
	seen := make(map[string]BlockDevice, len(payload.Devices))
	for _, row := range payload.Devices {
		if !kernelDevice.MatchString(row.Name) || !filesystemType.MatchString(row.Type) ||
			!deviceNumber.MatchString(row.DeviceNumber) || row.SizeBytes == nil || *row.SizeBytes < 0 || row.ReadOnly == nil {
			return nil, errStorage
		}
		device := BlockDevice{row.Name, row.Type, row.DeviceNumber, *row.SizeBytes, *row.ReadOnly}
		if previous, exists := seen[device.Name]; exists {
			if previous != device {
				return nil, errStorage
			}
			continue
		}
		seen[device.Name] = device
		devices = append(devices, device)
	}
	return devices, nil
}

func parseMounts(raw string) ([]Mount, error) {
	var payload struct {
		Filesystems []struct {
			Target       string `json:"target"`
			Filesystem   string `json:"fstype"`
			DeviceNumber string `json:"maj:min"`
		} `json:"filesystems"`
	}
	if !decodeInventoryJSON(raw, &payload) || payload.Filesystems == nil || len(payload.Filesystems) > maxMounts {
		return nil, errStorage
	}
	mounts := make([]Mount, 0, len(payload.Filesystems))
	for _, row := range payload.Filesystems {
		if !path.IsAbs(row.Target) || len(row.Target) > 900 || !utf8.ValidString(row.Target) ||
			strings.ContainsFunc(row.Target, unicode.IsControl) ||
			!filesystemType.MatchString(row.Filesystem) || !deviceNumber.MatchString(row.DeviceNumber) {
			return nil, errStorage
		}
		mounts = append(mounts, Mount{row.Target, row.Filesystem, row.DeviceNumber})
	}
	return mounts, nil
}

func parseResolvers(raw string) ([]Resolver, error) {
	lines := strings.Fields(raw)
	if len(lines) > maxResolvers {
		return nil, errNetwork
	}
	resolvers := make([]Resolver, 0, len(lines))
	seen := make(map[netip.Addr]bool, len(lines))
	for _, value := range lines {
		address, err := netip.ParseAddr(value)
		if err != nil || address.Zone() != "" && !networkName.MatchString(address.Zone()) {
			return nil, errNetwork
		}
		if !seen[address] {
			seen[address] = true
			resolvers = append(resolvers, Resolver{Address: address.String(), Priority: len(resolvers) + 1})
		}
	}
	return resolvers, nil
}
