package config

import "github.com/xtaci/kcp-go"

// KCPConfig describes the configuration of KCP.
type KCPConfig struct {
	MTU         int  `json:"mtu"`
	SendWindow  int  `json:"sndwnd"`
	RecvWindow  int  `json:"rcvwnd"`
	DataShard   int  `json:"datashard"`
	ParityShard int  `json:"parityshard"`
	ACKNoDelay  bool `json:"acknodelay"`
	NoDelay     bool `json:"nodelay"`
	Interval    int  `json:"interval"`
	Resend      int  `json:"resend"`
	NC          int  `json:"nc"`
}

// NewKCPConfig returns a new KCP config.
func NewKCPConfig() *KCPConfig {
	return &KCPConfig{
		MTU:         kcp.IKCP_MTU_DEF,
		SendWindow:  kcp.IKCP_WND_SND,
		RecvWindow:  kcp.IKCP_WND_RCV,
		DataShard:   10,
		ParityShard: 3,
		Interval:    kcp.IKCP_INTERVAL,
	}
}
