package audit_log

import (
	"time"

	"github.com/rs/xid"

	"github.com/turbot/pipe-fittings/v2/utils"
	"github.com/turbot/tailpipe-plugin-gcp/sources/cloud_logging_api"
	"github.com/turbot/tailpipe-plugin-gcp/sources/storage_bucket"
	"github.com/turbot/tailpipe-plugin-sdk/artifact_source"
	"github.com/turbot/tailpipe-plugin-sdk/artifact_source_config"
	"github.com/turbot/tailpipe-plugin-sdk/constants"
	"github.com/turbot/tailpipe-plugin-sdk/row_source"
	"github.com/turbot/tailpipe-plugin-sdk/schema"
	"github.com/turbot/tailpipe-plugin-sdk/table"
)

const RequestsLogTableIdentifier string = "gcp_requests_log"

type RequestsLogTable struct {
}

func (c *RequestsLogTable) Identifier() string {
	return RequestsLogTableIdentifier
}

func (c *RequestsLogTable) GetSourceMetadata() ([]*table.SourceMetadata[*RequestsLog], error) {
	defaultArtifactConfig := &artifact_source_config.ArtifactSourceConfigImpl{
		FileLayout: utils.ToStringPointer("projects/%{DATA:project_id}/logs/requests"),
	}

	return []*table.SourceMetadata[*RequestsLog]{
		{
			SourceName: cloud_logging_api.CloudLoggingAPISourceIdentifier,
			Mapper:     &RequestsLogMapper{},
		},
		{
			SourceName: storage_bucket.GcpStorageBucketSourceIdentifier,
			Mapper:     &RequestsLogMapper{},
			Options: []row_source.RowSourceOption{
				artifact_source.WithDefaultArtifactSourceConfig(defaultArtifactConfig),
				artifact_source.WithRowPerLine(),
			},
		},
		{
			SourceName: constants.ArtifactSourceIdentifier,
			Mapper:     &RequestsLogMapper{},
			Options: []row_source.RowSourceOption{
				artifact_source.WithDefaultArtifactSourceConfig(defaultArtifactConfig),
			},
		},
	}, nil
}

func (c *RequestsLogTable) EnrichRow(row *RequestsLog, sourceEnrichmentFields schema.SourceEnrichment) (*RequestsLog, error) {
	row.CommonFields = sourceEnrichmentFields.CommonFields

	row.TpID = xid.New().String()
	row.TpTimestamp = row.Timestamp
	row.TpIngestTimestamp = time.Now()
	row.TpIndex = schema.DefaultIndex
	row.TpDate = row.Timestamp.Truncate(24 * time.Hour)

	if row.AuthenticationInfo != nil {
		if row.AuthenticationInfo.PrincipalEmail != "" {
			row.TpUsernames = append(row.TpUsernames, row.AuthenticationInfo.PrincipalEmail)
			row.TpEmails = append(row.TpEmails, row.AuthenticationInfo.PrincipalEmail)
		}
		if row.AuthenticationInfo.PrincipalSubject != "" {
			row.TpUsernames = append(row.TpUsernames, row.AuthenticationInfo.PrincipalSubject)
		}
	}

	if row.HttpRequest != nil {
		if row.HttpRequest.LocalIp != "" {
			row.TpIps = append(row.TpIps, row.HttpRequest.LocalIp)
			row.TpSourceIP = &row.HttpRequest.LocalIp
		}
		if row.HttpRequest.RemoteIp != "" {
			row.TpIps = append(row.TpIps, row.HttpRequest.RemoteIp)
			row.TpDestinationIP = &row.HttpRequest.RemoteIp
		}
	}

	if row.RequestMetadata != nil {
		if row.RequestMetadata.CallerIp != "" {
			row.TpIps = append(row.TpIps, row.RequestMetadata.CallerIp)
			row.TpSourceIP = &row.RequestMetadata.CallerIp
		}
	}

	return row, nil
}

func (c *RequestsLogTable) GetDescription() string {
	return "GCP Request Logs track requests to Google Cloud services including application load balancer logs and Cloud Armor logs, capturing request events for security and compliance monitoring."
}
