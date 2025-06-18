package requests_log

import (
	"time"

	"google.golang.org/genproto/googleapis/cloud/audit"

	"github.com/turbot/tailpipe-plugin-sdk/schema"
)

// RequestsLog represents an enriched row ready for parquet writing
type RequestsLog struct {
	// embed required enrichment fields
	schema.CommonFields

	// Mandatory fields
	Timestamp    	 time.Time 			     `json:"timestamp"`
	ReceiveTimestamp time.Time 			     `json:"receiveTimestamp"`
	LogName      	 string    			     `json:"logName"`
	InsertId     	 string    			     `json:"insertId"`
	Severity     	 string    			     `json:"severity"`
	Trace        	 string    			     `json:"traceId"`
	SpanId       	 string    			     `json:"spanId"`
	TraceSampled	 bool    			     `json:"traceSampled"`
	JsonPayload 	 *requestLogPayload 	 `json:"jsonPayload" parquet:"type=JSON"`
	Resource 	 	 *requestLogResource 	 `json:"resource" parquet:"type=JSON"`
	HttpRequest      *requestLogHttpRequest  `json:"httpRequest" parquet:"type=JSON"`

}

func NewRequestsLog() *RequestsLog {
	return &RequestsLog{}
}

type requestLogPayload struct {
	Type string `json:"@type"`
	BackendTargetProjectNumber string `json:"backendTargetProjectNumber"`
	CacheDecision []string `json:"cacheDecision"`
	EnforcedSecurityPolicy *requestLogEnforcedSecurityPolicy `json:"enforcedSecurityPolicy"`
	PreviewSecurityPolicy *requestLogPreviewSecurityPolicy `json:"previewSecurityPolicy,omitempty"`
	SecurityPolicyRequestData *requestLogSecurityPolicyRequestData `json:"securityPolicyRequestData"`
	RemoteIp string `json:"remoteIp"`
	StatusDetails string `json:"statusDetails"`
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

type requestLogRemoteIpInfo struct {
	Asn int `json:"asn"`
	RegionCode string `json:"regionCode"`
}

type requestLogResource struct {
	Type string `json:"type"`
	Labels map[string]string `json:"labels" parquet:"type=JSON"`
}

type requestLogHttpRequest struct {
	RequestMethod                  string              `json:"requestMethod"`
	RequestUrl                     string              `json:"requestUrl"`
	RequestSize                    int64               `json:"requestSize"`
	Status                         int                 `json:"status"`
	ResponseSize                   int64               `json:"responseSize"`
	RemoteIp                       string              `json:"remoteIp"`
	Latency                        string              `json:"latency"`
	ServerIp                       string              `json:"serverIp"`
	UserAgent                      *string             `json:"userAgent,omitempty"`
}

func (a *RequestsLog) GetColumnDescriptions() map[string]string {
	return map[string]string{
		// CommonFields (inherited)

		"timestamp": "The date and time when the request was received, in ISO 8601 format.",
		"receive_timestamp": "The time when the log entry was received by Cloud Logging.",
		"log_name": "The name of the log that recorded the request, e.g., 'projects/[PROJECT_ID]/logs/requests'.",
		"insert_id": "A unique identifier for the log entry, used to prevent duplicate log entries.",
		"severity": "The severity level of the log entry (e.g., 'INFO', 'WARNING', 'ERROR', 'CRITICAL').",
		"trace_id": "The unique trace ID associated with the request, used for distributed tracing.",
		"span_id": "The span ID for the request, used in distributed tracing to identify specific operations.",
		"json_payload": "The JSON payload containing detailed information about the request, including security policy actions and remote IP.",
		"resource": "The monitored resource associated with the log entry, including type and labels.",
		"http_request": "Details about the HTTP request associated with the log entry, if available (present in application load balancer logs).",

		// requestLogPayload fields
		"type": "The type URL of the payload.",
		"backend_target_project_number": "The project number of the backend target.",
		"cache_decision": "A list of cache decisions made for the request.",
		"enforced_security_policy": "Details about the enforced security policy for the request.",
		"preview_security_policy": "Details about the preview security policy for the request, if any.",
		"security_policy_request_data": "Additional data about the security policy request.",
		"remote_ip": "The remote IP address from which the request originated.",
		"status_details": "Additional status details for the request.",

		// requestLogEnforcedSecurityPolicy fields
		"configured_action": "The action configured in the enforced security policy.",
		"name": "The name of the enforced or preview security policy.",
		"outcome": "The outcome of the enforced or preview security policy.",
		"priority": "The priority of the enforced or preview security policy.",
		"preconfigured_expression_ids": "List of preconfigured expression IDs in the enforced or preview security policy.",

		// requestLogSecurityPolicyRequestData fields
		"tls_ja3_fingerprint": "The JA3 TLS fingerprint for the request.",
		"tls_ja4_fingerprint": "The JA4 TLS fingerprint for the request.",

		// requestLogRemoteIpInfo fields
		"asn": "The ASN (Autonomous System Number) of the remote IP.",
		"region_code": "The region code of the remote IP.",

		// requestLogResource fields
		"type_resource": "The type of the monitored resource.",
		"labels": "Key-value labels associated with the resource.",

		// requestLogHttpRequest fields
		"request_method": "The HTTP method used for the request (e.g., GET, POST).",
		"request_url": "The URL requested.",
		"request_size": "The size of the HTTP request in bytes.",
		"status": "The HTTP response status code.",
		"response_size": "The size of the HTTP response in bytes.",
		"latency": "The latency of the request.",
		"server_ip": "The IP address of the server that handled the request.",
		"user_agent": "The user agent sent by the client.",

		// Override table specific tp_* column descriptions
		"tp_index": "The GCP project.",
	}
}
