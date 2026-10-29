package panel

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/url"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/KilluaAoki/XNode/common/nlog"
	"github.com/gorilla/websocket"
)

const (
	WSEventSyncConfig    = "sync.config"
	WSEventSyncUsers     = "sync.users"
	WSEventSyncUserDelta = "sync.user.delta"
	WSEventSyncDevices   = "sync.devices"
	WSEventSyncNodes     = "sync.nodes"
	WSEventReportDevices = "report.devices"
)

type WSEvent struct {
	Type        string
	Config      *NodeConfig
	Users       []User
	DeltaAction string
	DeltaUsers  []User

	DeviceUsers map[int][]string
	NodeID      int

	Nodes []MachineNode
}

type WSStatusChange struct {
	Connected bool
}

type wsMessage struct {
	Event     string          `json:"event"`
	Data      json.RawMessage `json:"data,omitempty"`
	Timestamp int64           `json:"timestamp,omitempty"`
}

// rawText defers the string conversion of a payload until a log line is
// actually written.
type rawText []byte

func (r rawText) String() string { return string(r) }

type syncConfigPayload struct {
	Config    NodeConfig `json:"config"`
	Timestamp int64      `json:"timestamp"`
	NodeID    int        `json:"node_id"`
}

type syncUsersPayload struct {
	Users     []User `json:"users"`
	Timestamp int64  `json:"timestamp"`
	NodeID    int    `json:"node_id"`
}

type syncUserDeltaPayload struct {
	Action    string `json:"action"`
	Users     []User `json:"users"`
	Timestamp int64  `json:"timestamp"`
	NodeID    int    `json:"node_id"`
}

type syncDevicesPayload struct {
	Users     map[int][]string `json:"users"`
	Timestamp int64            `json:"timestamp"`
	NodeID    int              `json:"node_id"`
}

type syncNodesPayload struct {
	Nodes []MachineNode `json:"nodes"`
}

type WSClientConfig struct {
	StatusInterval   time.Duration
	HandshakeTimeout time.Duration
	BackoffInitial   time.Duration
	BackoffMax       time.Duration
	MachineID        int

	// PingInterval is how often the client sends a ping control frame.
	PingInterval time.Duration
	// ReadTimeout drops a connection that has delivered nothing, not even a
	// pong, for this long. The panel also sends an app-level ping every 55s.
	ReadTimeout time.Duration
	// CloseWait bounds the wait for the panel to answer a close frame.
	CloseWait time.Duration
}

type WSClient struct {
	wsURL    string
	token    string
	nodeID   int
	onEvent  func(WSEvent)
	onStatus func(WSStatusChange)
	onPing   func() map[string]interface{}

	cfg WSClientConfig

	connected atomic.Bool

	writeCh atomic.Pointer[chan wsMessage]
}

func NewWSClient(wsURL string, token string, nodeID int, cfg WSClientConfig, onEvent func(WSEvent), onStatus func(WSStatusChange), onPing func() map[string]interface{}) *WSClient {
	if cfg.StatusInterval == 0 {
		cfg.StatusInterval = 10 * time.Second
	}
	if cfg.HandshakeTimeout == 0 {
		cfg.HandshakeTimeout = 15 * time.Second
	}
	if cfg.BackoffInitial == 0 {
		cfg.BackoffInitial = time.Second
	}
	if cfg.BackoffMax == 0 {
		cfg.BackoffMax = 60 * time.Second
	}
	if cfg.PingInterval == 0 {
		cfg.PingInterval = 30 * time.Second
	}
	if cfg.ReadTimeout == 0 {
		cfg.ReadTimeout = 120 * time.Second
	}
	if cfg.CloseWait == 0 {
		cfg.CloseWait = 5 * time.Second
	}
	return &WSClient{
		wsURL:    wsURL,
		token:    token,
		nodeID:   nodeID,
		cfg:      cfg,
		onEvent:  onEvent,
		onStatus: onStatus,
		onPing:   onPing,
	}
}

func (w *WSClient) IsConnected() bool { return w.connected.Load() }

func (w *WSClient) notifyStatus(connected bool) {
	if w.onStatus != nil {
		w.onStatus(WSStatusChange{Connected: connected})
	}
}

func (w *WSClient) Run(ctx context.Context) {
	backoff := w.cfg.BackoffInitial
	for {
		start := time.Now()
		err := w.connect(ctx)

		wasConnected := w.connected.Swap(false)
		if wasConnected {
			w.notifyStatus(false)
		}

		if err != nil {
			nlog.Core().Warn("ws disconnected", "error", err)
			if !wasConnected {
				w.notifyStatus(false)
			}
		}

		select {
		case <-ctx.Done():
			return
		default:
		}

		if time.Since(start) > 2*time.Minute {
			backoff = w.cfg.BackoffInitial
		}

		jitter := time.Duration(rand.Int63n(int64(backoff / 5)))
		wait := backoff + jitter

		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		if backoff < w.cfg.BackoffMax {
			backoff = min(backoff*2, w.cfg.BackoffMax)
		}
	}
}

func (w *WSClient) connect(ctx context.Context) error {
	u, err := url.Parse(w.wsURL)
	if err != nil {
		return fmt.Errorf("parse ws url: %w", err)
	}
	q := u.Query()
	q.Set("token", w.token)
	if w.cfg.MachineID > 0 {
		q.Set("machine_id", strconv.Itoa(w.cfg.MachineID))
	} else {
		q.Set("node_id", strconv.Itoa(w.nodeID))
	}
	u.RawQuery = q.Encode()

	nlog.Core().Debug("ws connecting", "url", redactToken(u.String(), w.token))

	dialer := websocket.Dialer{
		HandshakeTimeout: w.cfg.HandshakeTimeout,
	}
	conn, _, err := dialer.DialContext(ctx, u.String(), nil)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	conn.SetReadLimit(10 << 20)
	extendRead := func() { conn.SetReadDeadline(time.Now().Add(w.cfg.ReadTimeout)) }
	extendRead()
	conn.SetPongHandler(func(string) error {
		extendRead()
		return nil
	})

	var firstMsg wsMessage
	if err := conn.ReadJSON(&firstMsg); err != nil {
		return fmt.Errorf("read auth response: %w", err)
	}
	nlog.Core().Debug("ws recv", "event", firstMsg.Event, "data", string(firstMsg.Data))

	if firstMsg.Event == "error" {
		var errData struct {
			Message string `json:"message"`
		}
		if err := json.Unmarshal(firstMsg.Data, &errData); err != nil {
			return fmt.Errorf("auth failed (unable to parse error: %v)", err)
		}
		return fmt.Errorf("auth failed: %s", errData.Message)
	}

	writeCh := make(chan wsMessage, 16)
	w.writeCh.Store(&writeCh)
	defer w.writeCh.Store(nil)

	if firstMsg.Event != "auth.success" {
		w.connected.Store(true)
		w.notifyStatus(true)
		w.handleMessage(firstMsg)
	} else {
		w.connected.Store(true)
		w.notifyStatus(true)
	}

	reportTicker := time.NewTicker(w.cfg.StatusInterval)
	defer reportTicker.Stop()
	pingTicker := time.NewTicker(w.cfg.PingInterval)
	defer pingTicker.Stop()

	errCh := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			var msg wsMessage
			if err := conn.ReadJSON(&msg); err != nil {
				select {
				case errCh <- err:
				default:
				}
				return
			}
			extendRead()
			nlog.Core().Debug("ws recv", "event", msg.Event, "data", rawText(msg.Data))
			w.handleMessage(msg)
			if msg.Event == "ping" {
				select {
				case writeCh <- wsMessage{Event: "pong"}:
				default:
					nlog.Core().Warn("ws write channel full, skipping pong")
				}
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			conn.WriteMessage(websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
			// The deferred Close unblocks the reader if the panel never answers.
			select {
			case <-done:
			case <-time.After(w.cfg.CloseWait):
			}
			return nil

		case err := <-errCh:
			return fmt.Errorf("read: %w", err)

		case <-pingTicker.C:
			if err := conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(10*time.Second)); err != nil {
				return fmt.Errorf("ping: %w", err)
			}

		case <-reportTicker.C:
			if w.onPing != nil {
				msg := wsMessage{Event: "node.status"}
				if stats := w.onPing(); stats != nil {
					data, _ := json.Marshal(stats)
					msg.Data = data
					msg.Timestamp = time.Now().Unix()
				}
				select {
				case writeCh <- msg:
				default:
					nlog.Core().Warn("ws write channel full, skipping status push (network slow?)")
				}
			}

		case msg := <-writeCh:
			nlog.Core().Debug("ws send", "event", msg.Event, "data", rawText(msg.Data))
			conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := conn.WriteJSON(msg); err != nil {
				return fmt.Errorf("write: %w", err)
			}
		}
	}
}

func (w *WSClient) handleMessage(msg wsMessage) {
	switch msg.Event {
	case "ping":
		nlog.Core().Debug("ws received ping")

	case "auth.success":
		nlog.Core().Debug("ws auth confirmed")

	case WSEventSyncConfig:
		w.handleDataEvent(msg)

	case WSEventSyncUsers:
		w.handleDataEvent(msg)

	case WSEventSyncUserDelta:
		w.handleDataEvent(msg)

	case WSEventSyncDevices:
		w.handleDataEvent(msg)

	case WSEventSyncNodes:
		w.handleDataEvent(msg)

	default:
		nlog.Core().Debug("ws unknown event", "event", msg.Event)
	}
}

func (w *WSClient) handleDataEvent(msg wsMessage) {
	var event WSEvent
	event.Type = msg.Event

	decodeData := func(data []byte, target interface{}) error {
		var raw map[string]interface{}
		if err := json.Unmarshal(data, &raw); err != nil {
			return err
		}
		return decodeWeakRaw(raw, target)
	}

	switch msg.Event {
	case WSEventSyncConfig:
		nlog.Core().Debug("ws sync config event received")
		var p syncConfigPayload
		if err := decodeData(msg.Data, &p); err != nil {
			nlog.Core().Warn("ws: cannot decode config payload", "error", err)
			return
		}
		if p.Config.Protocol == "" {
			nlog.Core().Warn("ws: config payload missing protocol")
			return
		}
		event.Config = &p.Config
		if p.NodeID > 0 {
			event.NodeID = p.NodeID
		} else if p.Config.NodeID > 0 {
			event.NodeID = p.Config.NodeID
		}

	case WSEventSyncUsers:
		nlog.Core().Debug("ws sync users event received")
		// User lists can be large and match the REST shape, so they skip
		// the weak decode.
		var p syncUsersPayload
		if err := json.Unmarshal(msg.Data, &p); err != nil {
			nlog.Core().Warn("ws: cannot decode users payload", "error", err)
			return
		}
		if len(p.Users) == 0 {
			nlog.Core().Warn("ws: users payload empty")
			return
		}
		event.Users = p.Users
		event.NodeID = p.NodeID

	case WSEventSyncUserDelta:
		nlog.Core().Debug("ws sync user delta event received")
		var p syncUserDeltaPayload
		if err := json.Unmarshal(msg.Data, &p); err != nil {
			nlog.Core().Warn("ws: cannot decode user delta payload", "error", err)
			return
		}
		if p.Action == "" {
			nlog.Core().Warn("ws: user delta payload missing action")
			return
		}
		if len(p.Users) == 0 {
			nlog.Core().Warn("ws: user delta payload has no users")
			return
		}
		event.DeltaAction = p.Action
		event.DeltaUsers = p.Users
		event.NodeID = p.NodeID

	case WSEventSyncDevices:
		nlog.Core().Debug("ws sync devices event received")
		var p syncDevicesPayload
		if err := decodeData(msg.Data, &p); err != nil {
			nlog.Core().Warn("ws: cannot decode devices payload", "error", err)
			return
		}
		event.DeviceUsers = p.Users
		event.NodeID = p.NodeID

	case WSEventSyncNodes:
		nlog.Core().Info("ws sync nodes event received (machine node list changed)")
		var p syncNodesPayload
		if err := decodeData(msg.Data, &p); err != nil {
			nlog.Core().Warn("ws: cannot decode nodes payload", "error", err)
			return
		}
		event.Nodes = p.Nodes
	}

	w.onEvent(event)
}

func (w *WSClient) SendDeviceReport(devices map[int][]string) {
	w.SendDeviceReportForNode(0, devices)
}

func (w *WSClient) SendDeviceReportForNode(nodeID int, devices map[int][]string) {
	if !w.connected.Load() {
		return
	}

	var payload interface{}
	if nodeID > 0 {
		payload = map[string]interface{}{"node_id": nodeID, "devices": devices}
	} else {
		payload = devices
	}

	d, err := json.Marshal(payload)
	if err != nil {
		return
	}
	msg := wsMessage{
		Event:     WSEventReportDevices,
		Data:      d,
		Timestamp: time.Now().Unix(),
	}

	w.queue(msg)
}

func (w *WSClient) SendRaw(event string, data json.RawMessage) {
	if !w.connected.Load() {
		return
	}

	msg := wsMessage{
		Event:     event,
		Data:      data,
		Timestamp: time.Now().Unix(),
	}

	w.queue(msg)
}

// queue hands msg to the writer of the current connection. Messages sent
// while no connection is up are dropped.
func (w *WSClient) queue(msg wsMessage) {
	ch := w.writeCh.Load()
	if ch == nil {
		return
	}
	select {
	case *ch <- msg:
	default:
		nlog.Core().Warn("ws write channel full, skipping message", "event", msg.Event)
	}
}
