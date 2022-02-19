package model

type WakeOnLanHost struct {
	MacAddress      string `json:"MacAddress"`
	Name            string `json:"Name"`
	LatestIPAddress string `json:"LatestIPAddress"`
}

const WakeOnLanHostCollectionName = "wake_on_lan_hosts"
