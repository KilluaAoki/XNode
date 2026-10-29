package panel

import (
	"encoding/json"
	"fmt"
	"strings"
)

// UnmarshalJSON decodes a node config the same way as the panel HTTP path,
// tolerating the loose types panels send (numbers as strings and so on).
func (nc *NodeConfig) UnmarshalJSON(data []byte) error {
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*nc = NodeConfig{}
	return decodeWeakRaw(raw, nc)
}

func rawString(v interface{}) string {
	if v == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(v))
}
