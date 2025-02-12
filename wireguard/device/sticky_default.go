//go:build !linux

package device

import (
	"github.com/markpash/testing/wireguard/conn"
	"github.com/markpash/testing/wireguard/rwcancel"
)

func (device *Device) startRouteListener(bind conn.Bind) (*rwcancel.RWCancel, error) {
	return nil, nil
}
