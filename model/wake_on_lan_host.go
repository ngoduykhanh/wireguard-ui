package model

import (
	"errors"
	"strings"
	"time"
)

type WakeOnLanHost struct {
	MacAddress string     `json:"MacAddress"`
	Name       string     `json:"Name"`
	LatestUsed *time.Time `json:"LatestUsed"`
}

func (host WakeOnLanHost) ResolveResourceName() (string, error) {
	resourceName := strings.Trim(host.MacAddress, " \t\r\n\000")
	if len(resourceName) == 0 {
		return "", errors.New("mac Address is Empty")
	}
	resourceName = strings.ToUpper(resourceName)
	return strings.ReplaceAll(resourceName, ":", "-"), nil
}

const WakeOnLanHostCollectionName = "wake_on_lan_hosts"
