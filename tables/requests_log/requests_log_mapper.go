//nolint:staticcheck
package requests_log

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	loggingpb "cloud.google.com/go/logging/apiv2/loggingpb"

	"github.com/turbot/tailpipe-plugin-sdk/mappers"
)

type RequestsLogMapper struct {
}

func (m *RequestsLogMapper) Identifier() string {
	return "gcp_requests_log_mapper"
}

// flexibleInt64 can unmarshal from both string and int64 JSON values
type flexibleInt64 int64

func (f *flexibleInt64) UnmarshalJSON(data []byte) error {
	// Handle null or empty string
	if len(data) == 0 || string(data) == "null" || string(data) == `""` {
		*f = 0
		return nil
	}

	// Try to unmarshal as string first
	var str string
	if err := json.Unmarshal(data, &str); err == nil {
		// If it's an empty string, set to 0
		if str == "" {
			*f = 0
			return nil
		}
		// If it's a string, parse it
		val, err := strconv.ParseInt(str, 10, 64)
		if err != nil {
			return fmt.Errorf("failed to parse string as int64: %w", err)
		}
		*f = flexibleInt64(val)
		return nil
	}

	// If not a string, try as int64
	var val int64
	if err := json.Unmarshal(data, &val); err != nil {
		return fmt.Errorf("failed to unmarshal as int64 or string: %w", err)
	}
	*f = flexibleInt64(val)
	return nil
}

// sanitizeURL converts Unicode escape sequences (e.g., %u002e) to their actual characters
// to prevent URL parsing errors. This handles malformed URLs that contain Unicode escapes
// instead of proper URL percent-encoding.
func sanitizeURL(url string) string {
	// Match Unicode escape sequences like %u002e, %u0041, etc.
	re := regexp.MustCompile(`%u([0-9a-fA-F]{4})`)
	return re.ReplaceAllStringFunc(url, func(match string) string {
		// Extract the hex code (e.g., "002e" from "%u002e")
		hexCode := match[2:6] // Skip "%u" prefix
		code, err := strconv.ParseInt(hexCode, 16, 32)
		if err != nil {
			// If parsing fails, return the original match
			return match
		}
		// Convert to Unicode character
		return string(rune(code))
	})
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
		return nil, fmt.Errorf("expected loggingpb.LogEntry, string or []byte, got %T", a)
	}
}

func mapFromSDKType(item *loggingpb.LogEntry) (*RequestsLog, error) {
	// === 1. Filter by log name - only process requests logs ===
	// Requests logs have log names like "projects/{project}/logs/requests"
	logName := item.GetLogName()
	if !strings.Contains(logName, "/logs/requests") {
		// Not a requests log, skip it
		return nil, nil
	}

	// === 2. Early exit for non-HTTP(S) logs or those missing a payload ===
	if item.GetHttpRequest() == nil || item.GetJsonPayload() == nil {
		return nil, nil
	}

	row := NewRequestsLog()

	// === 2. Map common LogEntry fields ===
	row.Timestamp = item.GetTimestamp().AsTime()
	row.LogName = item.GetLogName()
	row.InsertId = item.GetInsertId()
	row.Severity = item.GetSeverity().String()
	row.ReceiveTimestamp = item.GetReceiveTimestamp().AsTime()
	row.Trace = item.GetTrace()   // Access Trace directly using GetTrace()
	row.SpanId = item.GetSpanId() // Access SpanID directly using GetSpanId()
	// TraceSampled is often inferred from SpanID or Trace, or may be a specific field
	row.TraceSampled = item.GetTraceSampled() // Assuming GetTraceSampled() exists for bool, else infer as before

	// === 3. Map Resource ===
	// Access Resource fields using GetResource() and its Get* methods
	if item.GetResource() != nil { // Check if resource object exists
		row.Resource = &RequestLogResource{
			Type:   item.GetResource().GetType(),
			Labels: item.GetResource().GetLabels(),
		}
	}

	// === 4. Map JsonPayload (for LB/Cloud Armor specific data) ===
	jsonPayload := item.GetJsonPayload().AsMap()
	row.BackendTargetProjectNumber = jsonPayload["backendTargetProjectNumber"].(string)
	// Handle CacheDecision specifically:
	if rawCacheDecision, ok := jsonPayload["cacheDecision"].([]interface{}); ok {
		// Iterate over the []interface{} and append string elements to row.CacheDecision
		for _, v := range rawCacheDecision {
			if s, ok := v.(string); ok {
				row.CacheDecision = append(row.CacheDecision, s)
			}
		}
	}
	row.RemoteIp = jsonPayload["remoteIp"].(string)
	row.StatusDetails = jsonPayload["statusDetails"].(string)

	securityPolicyMap := jsonPayload["enforcedSecurityPolicy"].(map[string]interface{})

	row.EnforcedSecurityPolicy = &RequestLogSecurityPolicy{
		// Direct assignments for guaranteed scalar fields
		ConfiguredAction: securityPolicyMap["configuredAction"].(string),
		Name:             securityPolicyMap["name"].(string),
		Outcome:          securityPolicyMap["outcome"].(string),
		Priority:         int(securityPolicyMap["priority"].(float64)), // JSON numbers are float64
	}

	// Handle PreconfiguredExpressionIds only if it exists *and* has values.
	if rawIds, ok := securityPolicyMap["preconfiguredExpressionIds"].([]interface{}); ok && len(rawIds) > 0 {
		row.EnforcedSecurityPolicy.PreconfiguredExpressionIds = make([]string, 0, len(rawIds))
		for _, id := range rawIds {
			row.EnforcedSecurityPolicy.PreconfiguredExpressionIds = append(row.EnforcedSecurityPolicy.PreconfiguredExpressionIds, id.(string))
		}
	}

	if previewPolicyMap, ok := jsonPayload["previewSecurityPolicy"].(map[string]interface{}); ok {
		// If it exists, initialize the PreviewSecurityPolicy struct
		row.PreviewSecurityPolicy = &RequestLogSecurityPolicy{
			// Direct assignments for its guaranteed scalar fields within previewPolicyMap
			ConfiguredAction: previewPolicyMap["configuredAction"].(string),
			Name:             previewPolicyMap["name"].(string),
			Outcome:          previewPolicyMap["outcome"].(string),
			Priority:         int(previewPolicyMap["priority"].(float64)), // JSON numbers are float64
		}

		// Handle PreconfiguredExpressionIds within PreviewSecurityPolicy only if it exists and has values.
		if rawIds, ok := previewPolicyMap["preconfiguredExpressionIds"].([]interface{}); ok && len(rawIds) > 0 {
			row.PreviewSecurityPolicy.PreconfiguredExpressionIds = make([]string, 0, len(rawIds))
			for _, id := range rawIds {
				row.PreviewSecurityPolicy.PreconfiguredExpressionIds = append(row.PreviewSecurityPolicy.PreconfiguredExpressionIds, id.(string))
			}
		}
	}

	// === 5. Map HTTPRequest (guaranteed to be present due to early exit) ===
	// No 'if' check needed here for item.GetHttpRequest() because we already filtered.
	httpRequestPb := item.GetHttpRequest()
	// Sanitize URLs to handle Unicode escape sequences that cause parsing errors
	requestUrl := sanitizeURL(httpRequestPb.GetRequestUrl())
	referer := sanitizeURL(httpRequestPb.GetReferer())
	row.HttpRequest = &RequestLogHttpRequest{
		RequestMethod: httpRequestPb.GetRequestMethod(),
		RequestUrl:    requestUrl,
		RequestSize:   httpRequestPb.GetRequestSize(),
		Referer:       referer,
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
	var log requestsLog
	if err := json.Unmarshal(itemBytes, &log); err != nil {
		return nil, fmt.Errorf("failed to parse requests log: %w", err)
	}

	// Filter by log name - only process requests logs
	// Requests logs have log names like "projects/{project}/logs/requests"
	if !strings.Contains(log.LogName, "/logs/requests") {
		// Not a requests log, skip it
		return nil, nil
	}

	row := NewRequestsLog()
	row.Timestamp = log.Timestamp
	row.ReceiveTimestamp = log.ReceiveTimestamp
	row.LogName = log.LogName
	row.InsertId = log.InsertId
	row.Severity = log.Severity
	row.Trace = log.Trace
	row.SpanId = log.SpanId
	row.Resource = &RequestLogResource{
		Type:   log.Resource.Type,
		Labels: log.Resource.Labels,
	}
	// Sanitize URLs to handle Unicode escape sequences that cause parsing errors
	requestUrl := sanitizeURL(log.HttpRequest.RequestURL)
	referer := sanitizeURL(log.HttpRequest.Referer)
	row.HttpRequest = &RequestLogHttpRequest{
		RequestMethod: log.HttpRequest.RequestMethod,
		RequestUrl:    requestUrl,
		RequestSize:   int64(log.HttpRequest.RequestSize),
		Status:        log.HttpRequest.Status,
		ResponseSize:  int64(log.HttpRequest.ResponseSize),
		UserAgent:     log.HttpRequest.UserAgent,
		RemoteIp:      log.HttpRequest.RemoteIP,
		ServerIp:      log.HttpRequest.ServerIP,
		Referer:       referer,
		Latency:       log.HttpRequest.Latency,
		CacheLookup:   log.HttpRequest.CacheLookup,
	}

	return row, nil
}

type requestsLog struct {
	InsertId         string       `json:"insertId"`
	LogName          string       `json:"logName"`
	Resource         *resource    `json:"resource,omitempty"`
	Timestamp        time.Time    `json:"timestamp"`
	Severity         string       `json:"severity"`
	JsonPayload      *jsonPayload `json:"jsonPayload,omitempty"`
	ReceiveTimestamp time.Time    `json:"receiveTimestamp"`
	Trace            string       `json:"trace,omitempty"`
	SpanId           string       `json:"spanId,omitempty"`
	HttpRequest      *httpRequest `json:"httpRequest,omitempty"`
}

type resource struct {
	Type   string            `json:"type"`
	Labels map[string]string `json:"labels"`
}

type jsonPayload struct {
	TypeName                   string                               `json:"@type"`
	BackendTargetProjectNumber string                               `json:"backendTargetProjectNumber"`
	CacheDecision              []string                             `json:"cacheDecision"`
	EnforcedSecurityPolicy     *requestLogEnforcedSecurityPolicy    `json:"enforcedSecurityPolicy"`
	PreviewSecurityPolicy      *requestLogPreviewSecurityPolicy     `json:"previewSecurityPolicy,omitempty"`
	SecurityPolicyRequestData  *requestLogSecurityPolicyRequestData `json:"securityPolicyRequestData"`
	RemoteIp                   string                               `json:"remoteIp"`
	StatusDetails              string                               `json:"statusDetails"`
}

type httpRequest struct {
	RequestMethod string        `json:"requestMethod"`
	RequestURL    string        `json:"requestUrl"`
	RequestSize   flexibleInt64 `json:"requestSize,omitempty"`
	Status        int32         `json:"status"`
	ResponseSize  flexibleInt64 `json:"responseSize,omitempty"`
	UserAgent     string        `json:"userAgent"`
	RemoteIP      string        `json:"remoteIp"`
	ServerIP      string        `json:"serverIp,omitempty"`
	Referer       string        `json:"referer,omitempty"`
	Latency       string        `json:"latency,omitempty"`
	CacheLookup   bool          `json:"cacheLookup,omitempty"`
}

type requestLogEnforcedSecurityPolicy struct {
	ConfiguredAction           string   `json:"configuredAction"`
	Name                       string   `json:"name"`
	Outcome                    string   `json:"outcome"`
	Priority                   int      `json:"priority"`
	PreconfiguredExpressionIds []string `json:"preconfiguredExpressionIds,omitempty"`
}

type requestLogPreviewSecurityPolicy struct {
	ConfiguredAction           string   `json:"configuredAction"`
	Name                       string   `json:"name"`
	Outcome                    string   `json:"outcome"`
	Priority                   int      `json:"priority"`
	PreconfiguredExpressionIds []string `json:"preconfiguredExpressionIds,omitempty"`
}

type requestLogSecurityPolicyRequestData struct {
	RemoteIpInfo      *requestLogRemoteIpInfo `json:"remoteIpInfo"`
	TlsJa3Fingerprint string                  `json:"tlsJa3Fingerprint"`
	TlsJa4Fingerprint string                  `json:"tlsJa4Fingerprint"`
}

type requestLogRemoteIpInfo struct {
	Asn        int    `json:"asn"`
	RegionCode string `json:"regionCode"`
}
