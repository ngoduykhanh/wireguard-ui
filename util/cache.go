package util

import "sync"

var IPToSubnetRange = map[string]uint16{}
var TgUseridToClientID = map[int64][]string{}
var TgUseridToClientIDMutex sync.RWMutex
var DBUsersToCRC32 = map[string]uint32{}
