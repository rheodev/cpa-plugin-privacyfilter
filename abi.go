package main

/*
#include <stdint.h>
#include <stdlib.h>

typedef struct {
	void* ptr;
	size_t len;
} cliproxy_buffer;

typedef int (*cliproxy_host_call_fn)(void*, const char*, const uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_host_free_fn)(void*, size_t);

typedef struct {
	uint32_t abi_version;
	void* host_ctx;
	cliproxy_host_call_fn call;
	cliproxy_host_free_fn free_buffer;
} cliproxy_host_api;

typedef int (*cliproxy_plugin_call_fn)(char*, uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_plugin_free_fn)(void*, size_t);
typedef void (*cliproxy_plugin_shutdown_fn)(void);

typedef struct {
	uint32_t abi_version;
	cliproxy_plugin_call_fn call;
	cliproxy_plugin_free_fn free_buffer;
	cliproxy_plugin_shutdown_fn shutdown;
} cliproxy_plugin_api;

extern int PrivacyFilterPluginCall(char*, uint8_t*, size_t, cliproxy_buffer*);
extern void PrivacyFilterPluginFree(void*, size_t);
extern void PrivacyFilterPluginShutdown(void);

static int privacyfilter_call_host(cliproxy_host_api* api, const char* method, const uint8_t* request, size_t request_len, cliproxy_buffer* response) {
	return api->call(api->host_ctx, method, request, request_len, response);
}

static void privacyfilter_free_host_buffer(cliproxy_host_api* api, void* ptr, size_t len) {
	api->free_buffer(ptr, len);
}
*/
import "C"

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"unsafe"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	log "github.com/sirupsen/logrus"
)

var privacyFilterABIState = struct {
	sync.RWMutex
	host         *C.cliproxy_host_api
	plugin       *privacyFilterPlugin
	shuttingDown bool
	inFlight     sync.WaitGroup
	// runtime is the state every plugin instance built by this library
	// shares, created by the first registration and never replaced while
	// the library is loaded; see runtimeState in main.go.
	runtime *runtimeState
}{}

const maxCGoBytesLen = C.size_t(1<<31 - 1)

type abiEnvelope struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *abiError       `json:"error,omitempty"`
}

type abiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type abiLifecycleRequest struct {
	ConfigYAML []byte `json:"config_yaml"`
	PluginDir  string `json:"plugin_dir,omitempty"`
}

// The host wraps every interceptor payload in an rpc_* struct that embeds
// the pluginapi type and adds host_callback_id. The two request hooks read
// that id through abiRequestInterceptRequest, so that pluginLog can write
// through the host under the request id of the call; the other hooks decode
// straight into their pluginapi types, and encoding/json ignores the extra
// member.
type abiRequestInterceptRequest struct {
	pluginapi.RequestInterceptRequest
	HostCallbackID string `json:"host_callback_id,omitempty"`
}

type abiRegistration struct {
	SchemaVersion uint32             `json:"schema_version"`
	Metadata      pluginapi.Metadata `json:"metadata"`
	Capabilities  abiCapabilities    `json:"capabilities"`
}

// abiCapabilities carries the capability flags of the registration. The JSON
// names are fixed by the host in internal/pluginhost/rpc_schema.go.
type abiCapabilities struct {
	RequestInterceptor     bool `json:"request_interceptor"`
	ResponseInterceptor    bool `json:"response_interceptor"`
	StreamChunkInterceptor bool `json:"response_stream_interceptor"`
	RequestLifecyclePlugin bool `json:"request_lifecycle_plugin"`
}

// abiSchemaVersion is the RPC contract version this plugin declares. Version
// 3 makes the host omit OriginalRequest and RequestBody on payload chunks of
// a stream, which this plugin never reads there; see HANDOVER.md. It is
// pinned to the constant rather than to pluginabi.SchemaVersion so that a
// later SDK bump cannot raise it past what the host at v7.2.149 accepts.
const abiSchemaVersion uint32 = pluginabi.SchemaVersionStreamChunkOmitRequestBody

// abiHostLogRequest is the payload of host.log, see pluginLog.
type abiHostLogRequest struct {
	HostCallbackID string         `json:"host_callback_id,omitempty"`
	Level          string         `json:"level"`
	Message        string         `json:"message"`
	Fields         map[string]any `json:"fields,omitempty"`
}

const (
	logLevelInfo  = "info"
	logLevelWarn  = "warn"
	logLevelError = "error"
)

type hostCallbackIDKey struct{}

func withHostCallbackID(ctx context.Context, id string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if id = strings.TrimSpace(id); id == "" {
		return ctx
	}
	return context.WithValue(ctx, hostCallbackIDKey{}, id)
}

func hostCallbackIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	id, _ := ctx.Value(hostCallbackIDKey{}).(string)
	return id
}

// pluginLog routes logs through host.log so they follow the host's log level,
// format and output and carry the request_id. The plugin's own logrus copy is
// a separate instance inside the shared library, so it is only a fallback for
// when no host is attached (tests, or a failed host call).
func pluginLog(ctx context.Context, level, message string, fields map[string]any) {
	if hostLog(hostCallbackIDFromContext(ctx), level, message, fields) {
		return
	}
	entry := log.WithFields(log.Fields(fields))
	switch level {
	case logLevelError:
		entry.Error(message)
	case logLevelWarn:
		entry.Warn(message)
	case logLevelInfo:
		entry.Info(message)
	default:
		entry.Debug(message)
	}
}

func hostLog(callbackID, level, message string, fields map[string]any) bool {
	privacyFilterABIState.RLock()
	host := privacyFilterABIState.host
	privacyFilterABIState.RUnlock()
	if host == nil || host.call == nil {
		return false
	}
	raw, errMarshal := json.Marshal(abiHostLogRequest{
		HostCallbackID: callbackID,
		Level:          level,
		Message:        message,
		Fields:         fields,
	})
	if errMarshal != nil {
		return false
	}

	method := C.CString(pluginabi.MethodHostLog)
	defer C.free(unsafe.Pointer(method))
	request := C.CBytes(raw)
	defer C.free(request)

	var response C.cliproxy_buffer
	status := C.privacyfilter_call_host(host, method, (*C.uint8_t)(request), C.size_t(len(raw)), &response)
	if response.ptr != nil && host.free_buffer != nil {
		defer C.privacyfilter_free_host_buffer(host, response.ptr, response.len)
	}
	if status != 0 {
		return false
	}
	if response.ptr == nil || response.len == 0 || response.len > maxCGoBytesLen {
		return true
	}
	var envelope abiEnvelope
	if errDecode := json.Unmarshal(C.GoBytes(response.ptr, C.int(response.len)), &envelope); errDecode != nil {
		return false
	}
	return envelope.OK
}

func main() {}

func inferPluginDir() string {
	sharedObjectPath := sharedLibraryPath()
	if sharedObjectPath == "" {
		return ""
	}
	return filepath.Dir(sharedObjectPath)
}

//export cliproxy_plugin_init
func cliproxy_plugin_init(host *C.cliproxy_host_api, plugin *C.cliproxy_plugin_api) C.int {
	if host == nil || plugin == nil {
		return 1
	}
	privacyFilterABIState.Lock()
	privacyFilterABIState.host = host
	privacyFilterABIState.shuttingDown = false
	privacyFilterABIState.Unlock()

	plugin.abi_version = C.uint32_t(pluginabi.ABIVersion)
	plugin.call = C.cliproxy_plugin_call_fn(C.PrivacyFilterPluginCall)
	plugin.free_buffer = C.cliproxy_plugin_free_fn(C.PrivacyFilterPluginFree)
	plugin.shutdown = C.cliproxy_plugin_shutdown_fn(C.PrivacyFilterPluginShutdown)
	return 0
}

//export PrivacyFilterPluginCall
func PrivacyFilterPluginCall(method *C.char, request *C.uint8_t, requestLen C.size_t, response *C.cliproxy_buffer) C.int {
	if response != nil {
		response.ptr = nil
		response.len = 0
	}
	if method == nil {
		writeABIResponse(response, abiErrorEnvelope("invalid_method", "method is required"))
		return 0
	}
	var requestBytes []byte
	if request != nil && requestLen > 0 {
		if requestLen > maxCGoBytesLen {
			writeABIResponse(response, abiErrorEnvelope("request_too_large", "request payload is too large"))
			return 0
		}
		requestBytes = C.GoBytes(unsafe.Pointer(request), C.int(requestLen))
	}
	raw, errHandle := handlePrivacyFilterABIMethod(context.Background(), C.GoString(method), requestBytes)
	if errHandle != nil {
		writeABIResponse(response, abiErrorEnvelope("plugin_error", errHandle.Error()))
		return 0
	}
	writeABIResponse(response, raw)
	return 0
}

//export PrivacyFilterPluginFree
func PrivacyFilterPluginFree(ptr unsafe.Pointer, _ C.size_t) {
	if ptr != nil {
		C.free(ptr)
	}
}

//export PrivacyFilterPluginShutdown
func PrivacyFilterPluginShutdown() {
	privacyFilterABIState.Lock()
	privacyFilterABIState.shuttingDown = true
	privacyFilterABIState.plugin = nil
	privacyFilterABIState.host = nil
	privacyFilterABIState.Unlock()
	privacyFilterABIState.inFlight.Wait()
}

func handlePrivacyFilterABIMethod(ctx context.Context, method string, request []byte) ([]byte, error) {
	switch method {
	case pluginabi.MethodPluginRegister, pluginabi.MethodPluginReconfigure:
		return handlePrivacyFilterRegister(ctx, method, request)
	}

	p, done, errPlugin := beginPrivacyFilterPluginCall()
	if errPlugin != nil {
		return nil, errPlugin
	}
	defer done()

	switch method {
	case pluginabi.MethodRequestInterceptBefore:
		return abiCall(request, func(req abiRequestInterceptRequest) (pluginapi.RequestInterceptResponse, error) {
			return p.InterceptRequestBeforeAuth(withHostCallbackID(ctx, req.HostCallbackID), req.RequestInterceptRequest)
		})
	case pluginabi.MethodRequestInterceptAfter:
		return abiCall(request, func(req abiRequestInterceptRequest) (pluginapi.RequestInterceptResponse, error) {
			return p.InterceptRequestAfterAuth(withHostCallbackID(ctx, req.HostCallbackID), req.RequestInterceptRequest)
		})
	case pluginabi.MethodResponseInterceptAfter:
		return abiCall(request, func(req pluginapi.ResponseInterceptRequest) (pluginapi.ResponseInterceptResponse, error) {
			return p.InterceptResponse(ctx, req)
		})
	case pluginabi.MethodResponseInterceptStreamChunk:
		return abiCall(request, func(req pluginapi.StreamChunkInterceptRequest) (pluginapi.StreamChunkInterceptResponse, error) {
			return p.InterceptStreamChunk(ctx, req)
		})
	case pluginabi.MethodRequestComplete:
		return abiCall(request, func(done pluginapi.RequestCompletion) (struct{}, error) {
			return struct{}{}, p.HandleRequestComplete(ctx, done)
		})
	default:
		return abiErrorEnvelope("unknown_method", "unknown method: "+method), nil
	}
}

// abiCall decodes the request into Req, runs fn and wraps its result into an
// OK envelope. A decode error or an error from fn is returned as is; the
// caller turns it into an error envelope.
func abiCall[Req, Resp any](request []byte, fn func(Req) (Resp, error)) ([]byte, error) {
	var req Req
	if errDecode := json.Unmarshal(request, &req); errDecode != nil {
		return nil, errDecode
	}
	resp, errCall := fn(req)
	if errCall != nil {
		return nil, errCall
	}
	return abiOKEnvelope(resp)
}

// handlePrivacyFilterRegister serves plugin.register and plugin.reconfigure.
// A configuration that does not build fails the first registration, as in
// the original plugin; on a reconfigure the previous instance stays in force
// and the rejected configuration is logged, because the host drops a plugin
// whose reconfigure fails, and the proxy would run on without a filter. A
// failure in the set-up of pseudonymize mode is no build error: that
// instance registers in the blocking state, see initPseudonymize.
func handlePrivacyFilterRegister(ctx context.Context, method string, request []byte) ([]byte, error) {
	var req abiLifecycleRequest
	if errDecode := json.Unmarshal(request, &req); errDecode != nil {
		return nil, errDecode
	}
	// The host re-registers the plugin on every configuration reload, with
	// requests in flight on the previous instance. Every instance joins the
	// same runtime state, so a request that began on the old instance stores
	// its table where the new instance's return path looks for it; see
	// runtimeState. The state is created here once and only read after.
	privacyFilterABIState.Lock()
	if privacyFilterABIState.runtime == nil {
		privacyFilterABIState.runtime = newRuntimeState()
	}
	rt := privacyFilterABIState.runtime
	privacyFilterABIState.Unlock()

	plugin, errBuild := buildPlugin(req.ConfigYAML, req.PluginDir, rt)
	if errBuild != nil {
		privacyFilterABIState.RLock()
		previous := privacyFilterABIState.plugin
		privacyFilterABIState.RUnlock()
		// The host drops a plugin whose reconfigure fails, which would silently
		// stop filtering. Keep the previous instance with its valid config
		// instead, report the rejected config loudly, and announce again what
		// that instance serves.
		if method == pluginabi.MethodPluginReconfigure && previous != nil {
			pluginLog(ctx, logLevelError, "privacy filter rejected new config, still using the previous valid config: "+errBuild.Error(), map[string]any{
				"error": errBuild.Error(),
			})
			return abiOKEnvelope(newABIRegistration(pluginMetadata(), capabilitiesFor(previous)))
		}
		return nil, errBuild
	}
	p, ok := plugin.Capabilities.RequestInterceptor.(*privacyFilterPlugin)
	if !ok || p == nil {
		return nil, fmt.Errorf("privacyfilter plugin registration returned invalid interceptor")
	}
	privacyFilterABIState.Lock()
	privacyFilterABIState.plugin = p
	privacyFilterABIState.shuttingDown = false
	privacyFilterABIState.Unlock()
	return abiOKEnvelope(newABIRegistration(plugin.Metadata, plugin.Capabilities))
}

// newABIRegistration is the answer to plugin.register: the schema version
// this plugin speaks, its metadata, and which hooks the instance serves. The
// host calls only what is announced here.
func newABIRegistration(metadata pluginapi.Metadata, caps pluginapi.Capabilities) abiRegistration {
	return abiRegistration{
		SchemaVersion: abiSchemaVersion,
		Metadata:      metadata,
		Capabilities: abiCapabilities{
			RequestInterceptor:     caps.RequestInterceptor != nil,
			ResponseInterceptor:    caps.ResponseInterceptor != nil,
			StreamChunkInterceptor: caps.StreamChunkInterceptor != nil,
			RequestLifecyclePlugin: caps.RequestLifecyclePlugin != nil,
		},
	}
}

func beginPrivacyFilterPluginCall() (*privacyFilterPlugin, func(), error) {
	privacyFilterABIState.Lock()
	defer privacyFilterABIState.Unlock()
	if privacyFilterABIState.shuttingDown {
		return nil, nil, fmt.Errorf("privacyfilter plugin is shutting down")
	}
	if privacyFilterABIState.plugin == nil {
		return nil, nil, fmt.Errorf("privacyfilter plugin is not registered")
	}
	privacyFilterABIState.inFlight.Add(1)
	return privacyFilterABIState.plugin, privacyFilterABIState.inFlight.Done, nil
}

func abiOKEnvelope(v any) ([]byte, error) {
	raw, errMarshal := json.Marshal(v)
	if errMarshal != nil {
		return nil, errMarshal
	}
	return json.Marshal(abiEnvelope{OK: true, Result: raw})
}

func abiErrorEnvelope(code, message string) []byte {
	raw, _ := json.Marshal(abiEnvelope{OK: false, Error: &abiError{Code: code, Message: message}})
	return raw
}

func writeABIResponse(response *C.cliproxy_buffer, raw []byte) {
	if response == nil || len(raw) == 0 {
		return
	}
	ptr := C.CBytes(raw)
	if ptr == nil {
		return
	}
	response.ptr = ptr
	response.len = C.size_t(len(raw))
}
