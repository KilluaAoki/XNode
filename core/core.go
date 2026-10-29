package core

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"

	"golang.org/x/time/rate"
)

type Capabilities struct {
	PerUserSpeedLimit    bool
	DeviceLimit          bool
	BuiltInTrafficStats  bool
	AliveIPTracking      bool
	ForceCloseConnection bool
	ForceCloseUser       bool
}

type TLSCert struct {
	CertPEM []byte
	KeyPEM  []byte
}

func (t TLSCert) HasCert() bool {
	return len(t.CertPEM) > 0 && len(t.KeyPEM) > 0
}

type Kernel interface {
	Name() string
	Protocols() []string
	Capabilities() Capabilities

	Start(nodeConfig *NodeSpec, users []UserSpec, tls TLSCert) error
	Stop()
	IsRunning() bool
	Reload(nodeConfig *NodeSpec, users []UserSpec, tls TLSCert) error

	AddUsers(users []UserSpec) (added int, err error)
	RemoveUsers(users []UserSpec) (removed int, err error)
	UpdateUsers(users []UserSpec) (added, removed int, err error)

	GetUserTraffic(ctx context.Context) (traffic map[int][2]int64, aliveIPs map[int]map[string]bool, connCount int, err error)
	CloseConnection(ctx context.Context, connID string) error
	CloseUserConnections(ctx context.Context, uuid string) error
	SetSpeedLimitFunc(fn func(uuid string) *rate.Limiter)
	SetDeviceLimitFunc(fn func(uuid string) (int, bool))
	UpdateGlobalDevices(users map[int][]string)
	ClearGlobalDevices()
	// UpdateRemoteDeviceCounts sets how many devices each user has online on
	// other nodes; nil clears it.
	UpdateRemoteDeviceCounts(counts map[int]int)
}

// ConnectionCounter is implemented by kernels that count accepted
// connections since the process started, across kernel restarts.
type ConnectionCounter interface {
	TotalConnections() int64
}

func ComputeHash(nc *NodeSpec, users []UserSpec) string {
	h := sha256.New()
	configData, _ := json.Marshal(nc)
	h.Write(configData)
	sorted := make([]UserSpec, len(users))
	copy(sorted, users)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })
	for _, u := range sorted {
		fmt.Fprintf(h, "%d:%s,", u.ID, u.UUID)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

func UserDiff(oldUsers, newUsers []UserSpec) (toAdd, toRemove []UserSpec) {
	oldMap := make(map[int]UserSpec, len(oldUsers))
	for _, u := range oldUsers {
		oldMap[u.ID] = u
	}
	newMap := make(map[int]UserSpec, len(newUsers))
	for _, u := range newUsers {
		newMap[u.ID] = u
	}

	for _, u := range newUsers {
		old, exists := oldMap[u.ID]
		if !exists || old.UUID != u.UUID {
			toAdd = append(toAdd, u)
		}
	}
	for _, u := range oldUsers {
		if cur, exists := newMap[u.ID]; !exists || cur.UUID != u.UUID {
			toRemove = append(toRemove, u)
		}
	}
	return
}
