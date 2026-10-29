package panel

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KilluaAoki/XNode/common/nlog"
	"github.com/KilluaAoki/XNode/conf"
	"github.com/go-viper/mapstructure/v2"
)

var (
	trafficMapPool = sync.Pool{New: func() interface{} { return make(map[string][2]int64) }}
	aliveMapPool   = sync.Pool{New: func() interface{} { return make(map[string][]string) }}
	onlineMapPool  = sync.Pool{New: func() interface{} { return make(map[string]int) }}
)

type Client struct {
	baseURL    string
	token      string
	nodeID     int
	nodeType   string
	machineID  int
	httpClient *http.Client

	configETag string
	userETag   string

	apiSuccess atomic.Uint64
	apiFailure atomic.Uint64

	legacy atomic.Bool

	aliveListUnsupported atomic.Bool
}

const defaultHTTPTimeout = 30 * time.Second

func NewClient(cfg conf.PanelConfig) *Client {
	timeout := time.Duration(cfg.Timeout) * time.Second
	if timeout <= 0 {
		timeout = defaultHTTPTimeout
	}
	return &Client{
		baseURL:   strings.TrimRight(cfg.URL, "/"),
		token:     cfg.Token,
		nodeID:    cfg.NodeID,
		nodeType:  cfg.NodeType,
		machineID: cfg.MachineID,
		httpClient: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				MaxIdleConns:        10,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     90 * time.Second,
			},
		},
	}
}

func (c *Client) ForNode(nodeID int) *Client {
	return &Client{
		baseURL:    c.baseURL,
		token:      c.token,
		nodeID:     nodeID,
		nodeType:   c.nodeType,
		machineID:  c.machineID,
		httpClient: c.httpClient,
	}
}

func (c *Client) ResetConfigETag() {
	c.configETag = ""
}

func (c *Client) Handshake() (*HandshakeResponse, error) {
	resp, err := c.doRequest("POST", "/api/v2/server/handshake", nil, "")
	if err != nil {
		return nil, fmt.Errorf("handshake: %w", err)
	}
	defer drainAndClose(resp.Body)

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("handshake status %d: %s", resp.StatusCode, body)
	}

	var hs HandshakeResponse
	if err := json.NewDecoder(resp.Body).Decode(&hs); err != nil {
		return nil, fmt.Errorf("decode handshake: %w", err)
	}
	if c.legacy.Load() {
		hs.WebSocket.Enabled = false
	}
	return &hs, nil
}

func (c *Client) Legacy() bool {
	return c.legacy.Load()
}

func (c *Client) ResolveIdentity() (bool, error) {
	if c.machineID > 0 || c.nodeType == "" {
		return false, nil
	}
	typed, status, err := c.probeNode("/api/v1/server/UniProxy/config")
	if err != nil {
		return c.legacy.Load(), fmt.Errorf("probe node: %w", err)
	}
	if status != http.StatusOK {
		return c.legacy.Load(), fmt.Errorf("probe node: status %d", status)
	}
	untyped, status, err := c.probeNode("/api/v2/server/config")
	if err != nil {
		return c.legacy.Load(), fmt.Errorf("probe v2 node: %w", err)
	}
	legacy := status != http.StatusOK || untyped != typed
	c.legacy.Store(legacy)
	return legacy, nil
}

func (c *Client) probeNode(path string) (string, int, error) {
	resp, err := c.doRequest("GET", path, nil, "")
	if err != nil {
		return "", 0, err
	}
	defer drainAndClose(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", resp.StatusCode, nil
	}
	var probe struct {
		Protocol   string `json:"protocol"`
		ServerPort any    `json:"server_port"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&probe); err != nil {
		return "", 0, fmt.Errorf("decode: %w", err)
	}
	return fmt.Sprintf("%s:%v", probe.Protocol, probe.ServerPort), resp.StatusCode, nil
}

func (c *Client) Report(traffic map[int][2]int64, alive map[int][]string, online map[int]int,
	cpu float64, mem, swap, disk [2]uint64,
	metrics map[string]interface{},
) error {
	if c.legacy.Load() {
		if err := c.PushTraffic(traffic); err != nil {
			return err
		}
		if err := errors.Join(c.PushAlive(alive), c.PushStatus(cpu, mem, swap, disk)); err != nil {
			nlog.Core().Warn("legacy report incomplete", "error", err)
		}
		return nil
	}
	payload := make(map[string]interface{})

	if len(traffic) > 0 {
		t := trafficMapPool.Get().(map[string][2]int64)
		for uid, d := range traffic {
			t[strconv.Itoa(uid)] = d
		}
		payload["traffic"] = t
		defer func() {
			for k := range t {
				delete(t, k)
			}
			trafficMapPool.Put(t)
		}()
	}

	if len(alive) > 0 {
		a := aliveMapPool.Get().(map[string][]string)
		for uid, ips := range alive {
			a[strconv.Itoa(uid)] = ips
		}
		payload["alive"] = a
		defer func() {
			for k := range a {
				delete(a, k)
			}
			aliveMapPool.Put(a)
		}()
	}

	if len(online) > 0 {
		o := onlineMapPool.Get().(map[string]int)
		for uid, count := range online {
			o[strconv.Itoa(uid)] = count
		}
		payload["online"] = o
		defer func() {
			for k := range o {
				delete(o, k)
			}
			onlineMapPool.Put(o)
		}()
	}

	status := map[string]interface{}{
		"cpu":  cpu,
		"mem":  map[string]interface{}{"total": mem[0], "used": mem[1]},
		"swap": map[string]interface{}{"total": swap[0], "used": swap[1]},
		"disk": map[string]interface{}{"total": disk[0], "used": disk[1]},
	}
	payload["status"] = status

	if len(metrics) > 0 {
		payload["metrics"] = metrics
	}

	return c.postJSON("/api/v2/server/report", payload)
}

func decodeWeakRaw(input map[string]interface{}, output interface{}) error {
	config := &mapstructure.DecoderConfig{
		Metadata:         nil,
		Result:           output,
		WeaklyTypedInput: true,
		TagName:          "json",
		DecodeHook: mapstructure.ComposeDecodeHookFunc(
			func(f, t reflect.Type, v interface{}) (interface{}, error) {
				if t == reflect.TypeOf(StringOrArray("")) && f.Kind() == reflect.Slice {
					arr, _ := v.([]interface{})
					var strs []string
					for _, x := range arr {
						if s, ok := x.(string); ok {
							strs = append(strs, s)
						}
					}
					return StringOrArray(strings.Join(strs, "\n")), nil
				}
				if t == reflect.TypeOf([]string(nil)) && f.Kind() == reflect.Map {
					return mapValues(v), nil
				}
				return v, nil
			},
			mapstructure.StringToSliceHookFunc(","),
		),
	}
	decoder, _ := mapstructure.NewDecoder(config)
	return decoder.Decode(input)
}

func mapValues(v interface{}) []interface{} {
	m, ok := v.(map[string]interface{})
	if !ok {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, errA := strconv.Atoi(keys[i])
		b, errB := strconv.Atoi(keys[j])
		if errA == nil && errB == nil {
			return a < b
		}
		return keys[i] < keys[j]
	})
	out := make([]interface{}, 0, len(m))
	for _, k := range keys {
		out = append(out, m[k])
	}
	return out
}

func (c *Client) configPath() string {
	if c.machineID > 0 {
		return "/api/v2/server/config"
	}
	return "/api/v1/server/UniProxy/config"
}

func (c *Client) userPath() string {
	if c.machineID > 0 {
		return "/api/v2/server/user"
	}
	return "/api/v1/server/UniProxy/user"
}

func (c *Client) GetConfig() (*NodeConfig, error) {
	resp, err := c.doRequest("GET", c.configPath(), nil, c.configETag)
	if err != nil {
		return nil, fmt.Errorf("get config: %w", err)
	}
	defer drainAndClose(resp.Body)

	if resp.StatusCode == http.StatusNotModified {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, body)
	}

	var raw map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode raw config: %w", err)
	}

	var cfg NodeConfig
	if err := decodeWeakRaw(raw, &cfg); err != nil {
		return nil, fmt.Errorf("weak decode config: %w", err)
	}

	if cfg.Protocol == "" {
		return nil, fmt.Errorf("invalid config: missing protocol")
	}

	if etag := resp.Header.Get("ETag"); etag != "" {
		c.configETag = etag
	}
	return &cfg, nil
}

func (c *Client) GetUsers() ([]User, error) {
	resp, err := c.doRequest("GET", c.userPath(), nil, c.userETag)
	if err != nil {
		return nil, fmt.Errorf("get users: %w", err)
	}
	defer drainAndClose(resp.Body)

	if resp.StatusCode == http.StatusNotModified {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, body)
	}

	var usersResp UsersResponse
	if err := json.NewDecoder(resp.Body).Decode(&usersResp); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}

	if etag := resp.Header.Get("ETag"); etag != "" {
		c.userETag = etag
	}
	return usersResp.Users, nil
}

// ErrAliveListUnsupported means the panel has no alivelist endpoint.
var ErrAliveListUnsupported = errors.New("panel does not support alivelist")

// GetAliveList fetches how many devices each user has online across all
// nodes, as counted by the panel from alive reports.
func (c *Client) GetAliveList() (map[int]int, error) {
	if c.aliveListUnsupported.Load() {
		return nil, ErrAliveListUnsupported
	}
	resp, err := c.doRequest("GET", "/api/v1/server/UniProxy/alivelist", nil, "")
	if err != nil {
		return nil, fmt.Errorf("get alive list: %w", err)
	}
	defer drainAndClose(resp.Body)

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound, http.StatusMethodNotAllowed:
		if c.aliveListUnsupported.CompareAndSwap(false, true) {
			nlog.Core().Info("panel has no alivelist endpoint, device limits use local and websocket data only")
		}
		return nil, ErrAliveListUnsupported
	default:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("alive list status %d: %s", resp.StatusCode, body)
	}

	var raw struct {
		Alive interface{} `json:"alive"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode alive list: %w", err)
	}
	return parseAliveCounts(raw.Alive), nil
}

// parseAliveCounts accepts {"uid": count} and the empty PHP array "[]".
func parseAliveCounts(v interface{}) map[int]int {
	out := make(map[int]int)
	m, _ := v.(map[string]interface{})
	for k, val := range m {
		uid, err := strconv.Atoi(strings.TrimSpace(k))
		if err != nil || uid <= 0 {
			continue
		}
		n, err := strconv.Atoi(rawString(val))
		if err != nil {
			if f, ok := val.(float64); ok {
				n = int(f)
			} else {
				continue
			}
		}
		if n > 0 {
			out[uid] = n
		}
	}
	return out
}

func (c *Client) PushTraffic(data map[int][2]int64) error {
	if len(data) == 0 {
		return nil
	}
	payload := make(map[string]interface{}, len(data))
	for uid, traffic := range data {
		payload[strconv.Itoa(uid)] = traffic
	}
	return c.postJSON("/api/v1/server/UniProxy/push", payload)
}

func (c *Client) PushAlive(data map[int][]string) error {
	if len(data) == 0 {
		return nil
	}
	payload := make(map[string]interface{}, len(data))
	for uid, ips := range data {
		payload[strconv.Itoa(uid)] = ips
	}
	return c.postJSON("/api/v1/server/UniProxy/alive", payload)
}

func (c *Client) PushStatus(cpu float64, mem, swap, disk [2]uint64) error {
	payload := map[string]interface{}{
		"cpu":  cpu,
		"mem":  map[string]interface{}{"total": mem[0], "used": mem[1]},
		"swap": map[string]interface{}{"total": swap[0], "used": swap[1]},
		"disk": map[string]interface{}{"total": disk[0], "used": disk[1]},
	}
	return c.postJSON("/api/v1/server/UniProxy/status", payload)
}

func (c *Client) ResetETags() {
	c.configETag = ""
	c.userETag = ""
}

func (c *Client) GetMachineNodes() (*MachineNodesResponse, error) {
	resp, err := c.doRequest("POST", "/api/v2/server/machine/nodes", nil, "")
	if err != nil {
		return nil, fmt.Errorf("get machine nodes: %w", err)
	}
	defer drainAndClose(resp.Body)

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("machine nodes status %d: %s", resp.StatusCode, body)
	}

	var out MachineNodesResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode machine nodes: %w", err)
	}
	return &out, nil
}

func (c *Client) ReportMachineStatus(cpu float64, mem, swap, disk [2]uint64, netIn, netOut float64) error {
	payload := map[string]interface{}{
		"cpu":  cpu,
		"mem":  map[string]interface{}{"total": mem[0], "used": mem[1]},
		"swap": map[string]interface{}{"total": swap[0], "used": swap[1]},
		"disk": map[string]interface{}{"total": disk[0], "used": disk[1]},
	}
	if netIn >= 0 && netOut >= 0 {
		payload["net"] = map[string]interface{}{"in_speed": netIn, "out_speed": netOut}
	}
	return c.postJSON("/api/v2/server/machine/status", payload)
}

func (c *Client) injectAuth(m map[string]interface{}) {
	m["token"] = c.token
	if c.machineID > 0 {
		m["machine_id"] = c.machineID
		if c.nodeID > 0 {
			m["node_id"] = c.nodeID
		}
	} else {
		m["node_id"] = c.nodeID
		if c.nodeType != "" {
			m["node_type"] = c.nodeType
		}
	}
}

func (c *Client) authQuery() url.Values {
	q := url.Values{}
	q.Set("token", c.token)
	if c.machineID > 0 {
		q.Set("machine_id", strconv.Itoa(c.machineID))
		if c.nodeID > 0 {
			q.Set("node_id", strconv.Itoa(c.nodeID))
		}
	} else {
		q.Set("node_id", strconv.Itoa(c.nodeID))
		if c.nodeType != "" {
			q.Set("node_type", c.nodeType)
		}
	}
	return q
}

func (c *Client) postJSON(path string, payload map[string]interface{}) error {
	c.injectAuth(payload)

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	resp, err := c.doRequest("POST", path, body, "")
	if err != nil {
		return fmt.Errorf("post %s: %w", path, err)
	}
	defer drainAndClose(resp.Body)

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("status %d: %s", resp.StatusCode, respBody)
	}
	c.apiSuccess.Add(1)
	return nil
}

// GET requests are idempotent, so transient failures are retried a few times
// before the caller sees them. Timeouts are not retried: the client has
// already waited the full timeout.
var (
	getRetryAttempts = 3
	getRetryDelay    = time.Second
)

func (c *Client) doRequest(method, path string, body []byte, ifNoneMatch string) (*http.Response, error) {
	if method != "GET" {
		return c.doRequestOnce(method, path, body, ifNoneMatch)
	}
	for attempt := 1; ; attempt++ {
		resp, err := c.doRequestOnce(method, path, body, ifNoneMatch)
		if attempt >= getRetryAttempts || !retryableGET(resp, err) {
			return resp, err
		}
		if resp != nil {
			drainAndClose(resp.Body)
		}
		nlog.Core().Debug("panel request retry", "path", path, "attempt", attempt, "error", err)
		time.Sleep(getRetryDelay * time.Duration(attempt))
	}
}

func retryableGET(resp *http.Response, err error) bool {
	if err != nil {
		var ne net.Error
		return !(errors.As(err, &ne) && ne.Timeout())
	}
	return resp.StatusCode >= 500
}

func (c *Client) doRequestOnce(method, path string, body []byte, ifNoneMatch string) (*http.Response, error) {
	fullURL := c.baseURL + path

	var bodyReader io.Reader
	if method == "GET" {
		fullURL += "?" + c.authQuery().Encode()
	} else if body != nil {
		bodyReader = bytes.NewReader(body)
	} else {
		authOnly := make(map[string]interface{})
		c.injectAuth(authOnly)
		merged, _ := json.Marshal(authOnly)
		bodyReader = bytes.NewReader(merged)
	}

	req, err := http.NewRequest(method, fullURL, bodyReader)
	if err != nil {
		return nil, c.redactErr(err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if ifNoneMatch != "" {
		req.Header.Set("If-None-Match", ifNoneMatch)
	}

	nlog.Core().Debug("panel request", "method", method, "path", path)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.apiFailure.Add(1)
		return nil, c.redactErr(err)
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		c.apiSuccess.Add(1)
	} else {
		c.apiFailure.Add(1)
	}

	nlog.Core().Debug("panel response", "method", method, "path", path, "status", resp.StatusCode)
	return resp, nil
}

// redactErr masks the token in *url.Error, whose message embeds the full
// request URL (GET requests carry the token in the query string).
func (c *Client) redactErr(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		ue.URL = redactToken(ue.URL, c.token)
	}
	return err
}

// redactToken replaces every occurrence of token in s, raw or query-escaped.
func redactToken(s, token string) string {
	if token == "" {
		return s
	}
	s = strings.ReplaceAll(s, url.QueryEscape(token), "***")
	return strings.ReplaceAll(s, token, "***")
}

func drainAndClose(body io.ReadCloser) {
	io.CopyN(io.Discard, body, 512)
	body.Close()
}

type APIMetrics struct {
	Success uint64
	Failure uint64
}

func (c *Client) SnapshotMetrics() APIMetrics {
	return APIMetrics{
		Success: c.apiSuccess.Load(),
		Failure: c.apiFailure.Load(),
	}
}
