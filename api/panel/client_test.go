package panel

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KilluaAoki/XNode/conf"
	"github.com/vmihailenco/msgpack/v5"
)

func newTestServer(handler http.HandlerFunc) (*httptest.Server, *Client) {
	ts := httptest.NewServer(handler)
	client := NewClient(conf.PanelConfig{
		URL:    ts.URL,
		Token:  "test-token",
		NodeID: 1,
	})
	return ts, client
}

func TestGetConfig_Success(t *testing.T) {
	ts, client := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/server/UniProxy/config" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.URL.Query().Get("token") != "test-token" {
			t.Errorf("missing token in query")
		}
		if r.URL.Query().Get("node_id") != "1" {
			t.Errorf("missing node_id in query")
		}
		w.Header().Set("ETag", `"etag-1"`)
		json.NewEncoder(w).Encode(NodeConfig{
			Protocol:   "shadowsocks",
			ServerPort: 111,
			Cipher:     "aes-128-gcm",
		})
	})
	defer ts.Close()

	cfg, err := client.GetConfig()
	if err != nil {
		t.Fatalf("GetConfig: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if cfg.Protocol != "shadowsocks" {
		t.Errorf("protocol: got %q", cfg.Protocol)
	}
	if cfg.ServerPort != 111 {
		t.Errorf("server_port: got %d", cfg.ServerPort)
	}
}

func TestGetConfig_NotModified(t *testing.T) {
	callCount := 0
	ts, client := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			w.Header().Set("ETag", `"etag-1"`)
			json.NewEncoder(w).Encode(NodeConfig{Protocol: "shadowsocks"})
			return
		}
		if r.Header.Get("If-None-Match") != `"etag-1"` {
			t.Errorf("expected If-None-Match header, got %q", r.Header.Get("If-None-Match"))
		}
		w.WriteHeader(http.StatusNotModified)
	})
	defer ts.Close()

	cfg, err := client.GetConfig()
	if err != nil || cfg == nil {
		t.Fatalf("first GetConfig: err=%v cfg=%v", err, cfg)
	}

	cfg, err = client.GetConfig()
	if err != nil {
		t.Fatalf("second GetConfig: %v", err)
	}
	if cfg != nil {
		t.Error("expected nil config for 304")
	}
}

func TestGetConfig_ServerError(t *testing.T) {
	setFastRetry(t)
	var calls atomic.Int32
	ts, client := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	})
	defer ts.Close()

	_, err := client.GetConfig()
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
	if n := calls.Load(); int(n) != getRetryAttempts {
		t.Errorf("requests = %d, want %d", n, getRetryAttempts)
	}
}

func TestGetUsers_Success(t *testing.T) {
	ts, client := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/server/UniProxy/user" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("ETag", `"users-etag-1"`)
		json.NewEncoder(w).Encode(UsersResponse{
			Users: []User{
				{ID: 1, UUID: "uuid-1", SpeedLimit: 3, DeviceLimit: 2},
				{ID: 2, UUID: "uuid-2", SpeedLimit: 0, DeviceLimit: 0},
			},
		})
	})
	defer ts.Close()

	users, err := client.GetUsers()
	if err != nil {
		t.Fatalf("GetUsers: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("users count: got %d", len(users))
	}
	if users[0].UUID != "uuid-1" {
		t.Errorf("user[0].uuid: got %q", users[0].UUID)
	}
}

func TestGetUsers_NotModified(t *testing.T) {
	callCount := 0
	ts, client := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			w.Header().Set("ETag", `"u-etag"`)
			json.NewEncoder(w).Encode(UsersResponse{Users: []User{{ID: 1, UUID: "u1"}}})
			return
		}
		w.WriteHeader(http.StatusNotModified)
	})
	defer ts.Close()

	users, _ := client.GetUsers()
	if len(users) != 1 {
		t.Fatalf("first call: got %d users", len(users))
	}
	users, err := client.GetUsers()
	if err != nil {
		t.Fatalf("second GetUsers: %v", err)
	}
	if users != nil {
		t.Error("expected nil for 304")
	}
}

func TestPushTraffic_Success(t *testing.T) {
	var received map[string]interface{}
	ts, client := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/server/UniProxy/push" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		json.NewDecoder(r.Body).Decode(&received)
		w.WriteHeader(http.StatusOK)
	})
	defer ts.Close()

	data := map[int][2]int64{
		1: {1024, 2048},
		2: {512, 256},
	}
	if err := client.PushTraffic(data); err != nil {
		t.Fatalf("PushTraffic: %v", err)
	}
	if received == nil {
		t.Fatal("server received nil payload")
	}
	if received["token"] != "test-token" {
		t.Errorf("token: got %v", received["token"])
	}
}

func TestPushTraffic_Empty(t *testing.T) {
	called := false
	ts, client := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	defer ts.Close()

	if err := client.PushTraffic(nil); err != nil {
		t.Fatalf("PushTraffic nil: %v", err)
	}
	if called {
		t.Error("should not call server for empty traffic")
	}
}

func TestPushAlive_Success(t *testing.T) {
	var received map[string]interface{}
	ts, client := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/server/UniProxy/alive" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		json.NewDecoder(r.Body).Decode(&received)
		w.WriteHeader(http.StatusOK)
	})
	defer ts.Close()

	data := map[int][]string{
		1: {"1.2.3.4", "5.6.7.8"},
	}
	if err := client.PushAlive(data); err != nil {
		t.Fatalf("PushAlive: %v", err)
	}
	if received == nil {
		t.Fatal("server received nil")
	}
}

func TestPushStatus_Success(t *testing.T) {
	var received map[string]interface{}
	ts, client := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/server/UniProxy/status" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		json.NewDecoder(r.Body).Decode(&received)
		w.WriteHeader(http.StatusOK)
	})
	defer ts.Close()

	err := client.PushStatus(50.0, [2]uint64{8192, 4096}, [2]uint64{2048, 1024}, [2]uint64{100000, 50000})
	if err != nil {
		t.Fatalf("PushStatus: %v", err)
	}
	if received["cpu"].(float64) != 50.0 {
		t.Errorf("cpu: got %v", received["cpu"])
	}
}

func TestResetETags(t *testing.T) {
	callCount := 0
	ts, client := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount <= 2 {
			w.Header().Set("ETag", `"e1"`)
			json.NewEncoder(w).Encode(NodeConfig{Protocol: "ss"})
			return
		}
		if r.Header.Get("If-None-Match") != "" {
			t.Errorf("expected no If-None-Match after reset, got %q", r.Header.Get("If-None-Match"))
		}
		json.NewEncoder(w).Encode(NodeConfig{Protocol: "ss"})
	})
	defer ts.Close()

	client.GetConfig()
	client.ResetETags()
	client.GetConfig()
}

func TestPushTraffic_ServerError(t *testing.T) {
	setFastRetry(t)
	var calls atomic.Int32
	ts, client := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("unavailable"))
	})
	defer ts.Close()

	data := map[int][2]int64{1: {100, 200}}
	err := client.PushTraffic(data)
	if err == nil {
		t.Fatal("expected error for 503")
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("POST requests = %d, want 1 (no retry)", n)
	}
}

func TestClient_NodeTypeInQuery(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("node_type") != "vmess" {
			t.Errorf("node_type: got %q, want vmess", r.URL.Query().Get("node_type"))
		}
		json.NewEncoder(w).Encode(NodeConfig{Protocol: "vmess"})
	}))
	defer ts.Close()

	client := NewClient(conf.PanelConfig{
		URL:      ts.URL,
		Token:    "tok",
		NodeID:   1,
		NodeType: "vmess",
	})
	client.GetConfig()
}

func TestStringOrArrayDecodeHook(t *testing.T) {
	input := map[string]interface{}{
		"padding_scheme": []interface{}{"stop=8", "0=30-30", "1=100-400"},
	}

	type TestConfig struct {
		PaddingScheme StringOrArray `json:"padding_scheme"`
	}

	var cfg TestConfig
	if err := decodeWeakRaw(input, &cfg); err != nil {
		t.Fatalf("decodeWeakRaw failed: %v", err)
	}

	want := "stop=8\n0=30-30\n1=100-400"
	if string(cfg.PaddingScheme) != want {
		t.Errorf("got %q, want %q", cfg.PaddingScheme, want)
	}
}

func TestStringOrArrayDecodeHook_String(t *testing.T) {
	input := map[string]interface{}{
		"padding_scheme": "stop=8\n0=30-30",
	}

	type TestConfig struct {
		PaddingScheme StringOrArray `json:"padding_scheme"`
	}

	var cfg TestConfig
	if err := decodeWeakRaw(input, &cfg); err != nil {
		t.Fatalf("decodeWeakRaw failed: %v", err)
	}

	want := "stop=8\n0=30-30"
	if string(cfg.PaddingScheme) != want {
		t.Errorf("got %q, want %q", cfg.PaddingScheme, want)
	}
}

func newIdentityServer(t *testing.T, nodeType string, v2Status int, v2Protocol string) (*httptest.Server, *Client, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var paths []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		switch r.URL.Path {
		case "/api/v1/server/UniProxy/config":
			json.NewEncoder(w).Encode(map[string]any{"protocol": "trojan", "server_port": 443})
		case "/api/v2/server/config":
			if v2Status != http.StatusOK {
				w.WriteHeader(v2Status)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"protocol": v2Protocol, "server_port": 443})
		case "/api/v2/server/handshake":
			json.NewEncoder(w).Encode(map[string]any{"websocket": map[string]any{"enabled": true, "ws_url": "ws://panel/ws"}})
		default:
			json.NewEncoder(w).Encode(map[string]any{"data": true})
		}
	}))
	client := NewClient(conf.PanelConfig{URL: ts.URL, Token: "test-token", NodeID: 1, NodeType: nodeType})
	return ts, client, func() []string {
		mu.Lock()
		defer mu.Unlock()
		out := append([]string(nil), paths...)
		paths = paths[:0]
		return out
	}
}

func TestResolveIdentity_CollisionUsesV1(t *testing.T) {
	ts, client, seen := newIdentityServer(t, "trojan", http.StatusOK, "vmess")
	defer ts.Close()

	legacy, err := client.ResolveIdentity()
	if err != nil || !legacy || !client.Legacy() {
		t.Fatalf("ResolveIdentity = %v, %v; want legacy", legacy, err)
	}
	seen()

	hs, err := client.Handshake()
	if err != nil {
		t.Fatalf("Handshake: %v", err)
	}
	if hs.WebSocket.Enabled {
		t.Fatal("websocket must be disabled when node_id is ambiguous")
	}

	seen()
	if err := client.Report(map[int][2]int64{1: {10, 20}}, map[int][]string{1: {"1.1.1.1"}}, map[int]int{1: 1}, 1, [2]uint64{}, [2]uint64{}, [2]uint64{}, nil); err != nil {
		t.Fatalf("Report: %v", err)
	}
	got := seen()
	want := []string{"/api/v1/server/UniProxy/push", "/api/v1/server/UniProxy/alive", "/api/v1/server/UniProxy/status"}
	if len(got) != len(want) {
		t.Fatalf("report paths = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("report paths = %v, want %v", got, want)
		}
	}
}

func TestResolveIdentity_UniqueKeepsV2(t *testing.T) {
	ts, client, seen := newIdentityServer(t, "trojan", http.StatusOK, "trojan")
	defer ts.Close()

	if legacy, err := client.ResolveIdentity(); err != nil || legacy {
		t.Fatalf("ResolveIdentity = %v, %v; want v2", legacy, err)
	}
	hs, err := client.Handshake()
	if err != nil || !hs.WebSocket.Enabled {
		t.Fatalf("Handshake = %+v, %v; want websocket enabled", hs, err)
	}
	seen()
	if err := client.Report(map[int][2]int64{1: {10, 20}}, nil, nil, 1, [2]uint64{}, [2]uint64{}, [2]uint64{}, nil); err != nil {
		t.Fatalf("Report: %v", err)
	}
	if got := seen(); len(got) != 1 || got[0] != "/api/v2/server/report" {
		t.Fatalf("report paths = %v, want v2 report", got)
	}
}

func TestResolveIdentity_V2Unavailable(t *testing.T) {
	ts, client, _ := newIdentityServer(t, "trojan", http.StatusNotFound, "")
	defer ts.Close()

	if legacy, err := client.ResolveIdentity(); err != nil || !legacy {
		t.Fatalf("ResolveIdentity = %v, %v; want legacy", legacy, err)
	}
}

func TestResolveIdentity_SkippedWithoutNodeType(t *testing.T) {
	ts, client, seen := newIdentityServer(t, "", http.StatusOK, "vmess")
	defer ts.Close()

	if legacy, err := client.ResolveIdentity(); err != nil || legacy {
		t.Fatalf("ResolveIdentity = %v, %v; want skipped", legacy, err)
	}
	if got := seen(); len(got) != 0 {
		t.Fatalf("unexpected requests %v", got)
	}
}

func setFastRetry(t *testing.T) {
	t.Helper()
	old := getRetryDelay
	getRetryDelay = time.Millisecond
	t.Cleanup(func() { getRetryDelay = old })
}

func TestGetConfig_RetriesTransientError(t *testing.T) {
	setFastRetry(t)
	var calls atomic.Int32
	ts, client := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		json.NewEncoder(w).Encode(NodeConfig{Protocol: "vmess", ServerPort: 1})
	})
	defer ts.Close()

	cfg, err := client.GetConfig()
	if err != nil || cfg == nil || cfg.Protocol != "vmess" {
		t.Fatalf("GetConfig = %+v, %v", cfg, err)
	}
	if n := calls.Load(); n != 2 {
		t.Errorf("requests = %d, want 2", n)
	}
}

func TestGetUsers_NoRetryOn4xx(t *testing.T) {
	setFastRetry(t)
	var calls atomic.Int32
	ts, client := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusForbidden)
	})
	defer ts.Close()

	if _, err := client.GetUsers(); err == nil {
		t.Fatal("expected error for 403")
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("requests = %d, want 1", n)
	}
}

func TestGetAliveList(t *testing.T) {
	var body string
	ts, client := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/server/UniProxy/alivelist" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Write([]byte(body))
	})
	defer ts.Close()

	body = `{"alive":{"1":2,"2":"3","x":1,"4":0}}`
	got, err := client.GetAliveList()
	if err != nil || len(got) != 2 || got[1] != 2 || got[2] != 3 {
		t.Fatalf("GetAliveList = %v, %v", got, err)
	}

	body = `{"alive":[]}`
	got, err = client.GetAliveList()
	if err != nil || got == nil || len(got) != 0 {
		t.Fatalf("empty alive list = %v, %v", got, err)
	}
}

func TestGetAliveList_Unsupported(t *testing.T) {
	var calls atomic.Int32
	ts, client := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusNotFound)
	})
	defer ts.Close()

	for i := 0; i < 2; i++ {
		if _, err := client.GetAliveList(); !errors.Is(err, ErrAliveListUnsupported) {
			t.Fatalf("err = %v, want ErrAliveListUnsupported", err)
		}
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("requests = %d, want 1 after the endpoint is known missing", n)
	}
}

func TestGetUsers_Msgpack(t *testing.T) {
	ts, client := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Response-Format") != "msgpack" {
			t.Errorf("X-Response-Format = %q", r.Header.Get("X-Response-Format"))
		}
		body, err := msgpack.Marshal(map[string]any{
			"users": []map[string]any{
				{"id": 1, "uuid": "uuid-1", "speed_limit": 3, "device_limit": 2},
				{"id": 2, "uuid": "uuid-2"},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/x-msgpack")
		w.Header().Set("ETag", `"mp-etag"`)
		w.Write(body)
	})
	defer ts.Close()

	users, err := client.GetUsers()
	if err != nil {
		t.Fatalf("GetUsers: %v", err)
	}
	if len(users) != 2 || users[0].UUID != "uuid-1" || users[0].SpeedLimit != 3 || users[0].DeviceLimit != 2 || users[1].ID != 2 {
		t.Fatalf("users = %+v", users)
	}
	if client.userETag != `"mp-etag"` {
		t.Errorf("userETag = %q", client.userETag)
	}
}

func TestNewClient_Timeout(t *testing.T) {
	if got := NewClient(conf.PanelConfig{}).httpClient.Timeout; got != defaultHTTPTimeout {
		t.Errorf("default timeout = %v", got)
	}
	if got := NewClient(conf.PanelConfig{Timeout: 5}).httpClient.Timeout; got != 5*time.Second {
		t.Errorf("timeout = %v", got)
	}
}
