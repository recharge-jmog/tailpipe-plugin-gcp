//nolint:staticcheck
package requests_log

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"cloud.google.com/go/logging"
	loggingpb "cloud.google.com/go/logging/apiv2/loggingpb"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/turbot/pipe-fittings/v2/utils"
	"github.com/turbot/tailpipe-plugin-sdk/mappers"
)

type RequestsLogMapper struct {
}

func (m *RequestsLogMapper) Identifier() string {
	return "gcp_requests_log_mapper"
}

func (m *RequestsLogMapper) Map(_ context.Context, a any, _ ...mappers.MapOption[*RequestsLog]) (*RequestsLog, error) {
	switch v := a.(type) {
	case string:
		return mapFromBucketJson([]byte(v))
	case *loggingpb.LogEntry:
		return mapFromSDKType(v)
	case []byte:
		return mapFromBucketJson(v)
	default:
		return nil, fmt.Errorf("expected logging.Entry, string or []byte, got %T", a)
	}
}

func mapFromSDKType(item *loggingpb.LogEntry) (*RequestsLog, error) {
    // === 1. Early exit for non-HTTP(S) logs or those missing a payload ===
    if item.GetHttpRequest() == nil || item.GetJsonPayload() == nil {
        return nil, nil
    }

    row := NewRequestsLog()

    // === 2. Map common LogEntry fields ===
    row.Timestamp = item.GetTimestamp().AsTime()
    row.LogName = item.GetLogName()
    row.InsertID = item.GetInsertId()
    row.Severity = item.GetSeverity().String()
    row.ReceiveTimestamp = item.GetReceiveTimestamp().AsTime()
    row.Trace = item.GetTrace() // Access Trace directly using GetTrace()
    row.SpanID = item.GetSpanId() // Access SpanID directly using GetSpanId()
    // TraceSampled is often inferred from SpanID or Trace, or may be a specific field
    row.TraceSampled = item.GetTraceSampled() // Assuming GetTraceSampled() exists for bool, else infer as before

    // === 3. Map Resource ===
    // Access Resource fields using GetResource() and its Get* methods
    if item.GetResource() != nil { // Check if resource object exists
        row.Resource = &requestLogResource{
            Type:   item.GetResource().GetType(),
            Labels: item.GetResource().GetLabels(),
        }
    }

    // === 4. Map JsonPayload (for LB/Cloud Armor specific data) ===
    if item.GetJsonPayload() != nil {
        var lbPayload LoadBalancerRequestPayload // Your custom struct
        jsonBytes, err := item.GetJsonPayload().MarshalJSON()
        if err != nil {
            return nil, fmt.Errorf("error marshaling jsonPayload to bytes for Load Balancer log: %w", err)
        }
        err = json.Unmarshal(jsonBytes, &lbPayload)
        if err != nil {
            return nil, fmt.Errorf("error unmarshaling jsonPayload to LoadBalancerRequestPayload: %w", err)
        }
        row.RequestPayload = &lbPayload
    }

    // === 5. Map HTTPRequest (guaranteed to be present due to early exit) ===
    // No 'if' check needed here for item.GetHttpRequest() because we already filtered.
    httpRequestPb := item.GetHttpRequest()
    row.HttpRequest = &requestLogHttpRequest{
        RequestMethod: httpRequestPb.GetRequestMethod(),
        RequestUrl:    httpRequestPb.GetRequestUrl(),
        RequestSize:   httpRequestPb.GetRequestSize(),
        Referer:       httpRequestPb.GetReferer(),
        UserAgent:     httpRequestPb.GetUserAgent(),
        Status:        httpRequestPb.GetStatus(),
        ResponseSize:  httpRequestPb.GetResponseSize(),
        RemoteIp:      httpRequestPb.GetRemoteIp(),
        Latency:       httpRequestPb.GetLatency().String(), // Latency is a duration type in Protobuf
        ServerIp:      httpRequestPb.GetServerIp(),
        Protocol:      httpRequestPb.GetProtocol(),
    }

    return row, nil
}

func mapFromBucketJson(itemBytes []byte) (*RequestsLog, error) {
	var log struct {
		Timestamp        time.Time              `json:"timestamp"`
		ReceiveTimestamp time.Time              `json:"receiveTimestamp"`
		LogName          string                 `json:"logName"`
		InsertId         string                 `json:"insertId"`
		Severity         string                 `json:"severity"`
		Trace            string                 `json:"trace"`
		SpanId           string                 `json:"spanId"`
		JsonPayload      *requestLogPayload     `json:"jsonPayload"`
		Resource         *requestLogResource    `json:"resource"`
		HttpRequest      *requestLogHttpRequest `json:"httpRequest"`
	}
	if err := json.Unmarshal(itemBytes, &log); err != nil {
		return nil, fmt.Errorf("failed to parse requests log: %w", err)
	}
	row := NewRequestsLog()
	row.Timestamp = log.Timestamp
	row.ReceiveTimestamp = log.ReceiveTimestamp
	row.LogName = log.LogName
	row.InsertId = log.InsertId
	row.Severity = log.Severity
	row.Trace = log.Trace
	row.SpanId = log.SpanId
	row.JsonPayload = log.JsonPayload
	row.Resource = log.Resource
	row.HttpRequest = log.HttpRequest
	return row, nil
}

type requestsLog struct {
	InsertID         string            `json:"insertId"`
	LogName          string            `json:"logName"`
	Resource         *resource         `json:"resource,omitempty"`
	Timestamp        time.Time         `json:"timestamp"`
	Severity         string            `json:"severity"`
	JsonPayload      *jsonPayload      `json:"jsonPayload,omitempty"`
	ReceiveTimestamp time.Time         `json:"receiveTimestamp"`
	Trace            string            `json:"trace,omitempty"`
	SpanID           string            `json:"spanId,omitempty"`
	HTTPRequest      *httpRequest      `json:"httpRequest,omitempty"`
}

type resource struct {
	Type   string            `json:"type"`
	Labels map[string]string `json:"labels"`
}

type jsonPayload struct {
	TypeName              string              `json:"@type"`
	BackendTargetProjectNumber string `json:"backendTargetProjectNumber"`
	CacheDecision []string `json:"cacheDecision"`
	EnforcedSecurityPolicy *requestLogEnforcedSecurityPolicy `json:"enforcedSecurityPolicy"`
	PreviewSecurityPolicy *requestLogPreviewSecurityPolicy `json:"previewSecurityPolicy,omitempty"`
	SecurityPolicyRequestData *requestLogSecurityPolicyRequestData `json:"securityPolicyRequestData"`
	RemoteIp string `json:"remoteIp"`
	StatusDetails string `json:"statusDetails"`
}


type httpRequest struct {
	RequestMethod                  string `json:"requestMethod"`
	RequestURL                     string `json:"requestUrl"`
	RequestSize                    string `json:"requestSize,omitempty"`
	Status                         int    `json:"status"`
	ResponseSize                   string `json:"responseSize,omitempty"`
	UserAgent                      string `json:"userAgent"`
	RemoteIP                       string `json:"remoteIp"`
	ServerIP                       string `json:"serverIp,omitempty"`
	Referer                        string `json:"referer,omitempty"`
	Latency                        string `json:"latency,omitempty"`
	CacheLookup                    bool   `json:"cacheLookup,omitempty"`
}

type requestLogEnforcedSecurityPolicy struct {
	ConfiguredAction string `json:"configuredAction"`
	Name string `json:"name"`
	Outcome string `json:"outcome"`
	Priority int `json:"priority"`
	PreconfiguredExpressionIds []string `json:"preconfiguredExpressionIds,omitempty"`
}

type requestLogPreviewSecurityPolicy struct {
	ConfiguredAction string `json:"configuredAction"`
	Name string `json:"name"`
	Outcome string `json:"outcome"`
	Priority int `json:"priority"`
	PreconfiguredExpressionIds []string `json:"preconfiguredExpressionIds,omitempty"`
}

type requestLogSecurityPolicyRequestData struct {
	RemoteIpInfo *requestLogRemoteIpInfo `json:"remoteIpInfo"`
	TlsJa3Fingerprint string `json:"tlsJa3Fingerprint"`
	TlsJa4Fingerprint string `json:"tlsJa4Fingerprint"`
}

