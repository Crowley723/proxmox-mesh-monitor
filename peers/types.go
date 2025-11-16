package peers

type Peer struct {
	Hostname string   `json:"hostname"`
	Address  string   `json:"address"`
	Role     PeerRole `json:"role"`
}

type PeerRegistry struct {
	Peers []Peer `json:"peers"`
}
