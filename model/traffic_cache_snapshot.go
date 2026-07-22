package model

// TrafficCacheSnapshot persists WireGuard traffic bucket history (ring buffer) across
// wireguard-ui process restarts. Live delta state (prev counters) is not stored and is
// re-established against the kernel on the next samples.
type TrafficCacheSnapshot struct {
	Version int `json:"version"`

	BaseBucketMs   int64 `json:"base_bucket_ms"`
	MaxBaseBuckets int   `json:"max_base_buckets"`

	BaseBucketID []int64            `json:"base_bucket_id"`
	RxSumBps     []float64          `json:"rx_sum_bps"`
	RxCount      []int              `json:"rx_count"`
	TxSumBps     []float64          `json:"tx_sum_bps"`
	TxCount      []int              `json:"tx_count"`
	TxMaxBps     []float64          `json:"tx_max_bps"`
	TopPeerBps   []float64          `json:"top_peer_bps"`
	TopPeerKey   []string           `json:"top_peer_key"`
	PeerRxBytes  []map[string]int64 `json:"peer_rx_bytes"`
	PeerTxBytes  []map[string]int64 `json:"peer_tx_bytes"`

	LastRxRate float64   `json:"last_rx_rate"`
	LastTxRate float64   `json:"last_tx_rate"`
	RecentRx   []float64 `json:"recent_rx"`
	RecentTx   []float64 `json:"recent_tx"`

	TotalRxBytes   int64 `json:"total_rx_bytes"`
	TotalTxBytes   int64 `json:"total_tx_bytes"`
	LastUpdateAtMs int64 `json:"last_update_at_ms"`
	HasDeltaSample bool  `json:"has_delta_sample"`
}
