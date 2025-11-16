package peers

const (
	ConstPeersFile = "peers.json"
)

type PeerRole string

const (
	RoleMember    PeerRole = "member"
	RoleKeymaster PeerRole = "keymaster"
)
