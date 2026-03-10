package formatter_test

import (
	"testing"

	"github.com/praetorian-inc/capability-sdk/pkg/capmodel"
	"github.com/praetorian-inc/capability-sdk/pkg/formatter"
	"github.com/stretchr/testify/assert"
)

func TestFromModel_Asset(t *testing.T) {
	f := formatter.FromModel("test-scanner", capmodel.Asset{
		DNS:  "subdomain.example.com",
		Name: "subdomain.example.com",
	})

	assert.Equal(t, "Asset: subdomain.example.com", f.Title)
	assert.Equal(t, "subdomain.example.com", f.Location.Host)
	assert.Equal(t, "test-scanner", f.Source)
	assert.Equal(t, formatter.SeverityInfo, f.Severity)
	assert.Equal(t, "subdomain.example.com", f.Metadata["name"])
}

func TestFromModel_AssetPointer(t *testing.T) {
	f := formatter.FromModel("test-scanner", &capmodel.Asset{
		DNS:  "subdomain.example.com",
		Name: "subdomain.example.com",
	})

	assert.Equal(t, "Asset: subdomain.example.com", f.Title)
	assert.Equal(t, "subdomain.example.com", f.Location.Host)
}

func TestFromModel_Risk(t *testing.T) {
	f := formatter.FromModel("vuln-scanner", capmodel.Risk{
		Name:   "Open S3 Bucket",
		Status: "open",
		Target: capmodel.Asset{DNS: "s3.example.com", Name: "s3.example.com"},
	})

	assert.Equal(t, "Open S3 Bucket", f.Title)
	assert.Equal(t, "s3.example.com", f.Location.Host)
	assert.Equal(t, "vuln-scanner", f.Source)
	assert.Equal(t, "open", f.Metadata["status"])
}

func TestFromModel_Domain(t *testing.T) {
	f := formatter.FromModel("dns-enum", capmodel.Domain{Domain: "example.com"})

	assert.Equal(t, "Domain: example.com", f.Title)
	assert.Equal(t, "example.com", f.Location.Host)
	assert.Equal(t, formatter.SeverityInfo, f.Severity)
}

func TestFromModel_IP(t *testing.T) {
	f := formatter.FromModel("ip-scanner", capmodel.IP{IP: "10.0.0.1"})

	assert.Equal(t, "IP: 10.0.0.1", f.Title)
	assert.Equal(t, "10.0.0.1", f.Location.Host)
}

func TestFromModel_Port(t *testing.T) {
	f := formatter.FromModel("port-scanner", capmodel.Port{
		Protocol: "tcp",
		Port:     443,
		Service:  "https",
		Parent:   capmodel.Asset{DNS: "example.com"},
	})

	assert.Equal(t, "Port: 443/tcp", f.Title)
	assert.Equal(t, 443, f.Location.Port)
	assert.Equal(t, "tcp", f.Location.Protocol)
	assert.Equal(t, "example.com", f.Location.Host)
	assert.Equal(t, "https", f.Metadata["service"])
}

func TestFromModel_WebApplication(t *testing.T) {
	f := formatter.FromModel("webapp-scan", capmodel.WebApplication{
		PrimaryURL: "https://example.com",
		Name:       "Example App",
	})

	assert.Equal(t, "WebApp: Example App", f.Title)
	assert.Equal(t, "https://example.com", f.Location.URL)
}

func TestFromModel_Webpage(t *testing.T) {
	f := formatter.FromModel("crawler", capmodel.Webpage{
		URL: "https://example.com/page",
	})

	assert.Equal(t, "Webpage: https://example.com/page", f.Title)
	assert.Equal(t, "https://example.com/page", f.Location.URL)
}

func TestFromModel_AWSResource(t *testing.T) {
	f := formatter.FromModel("aws-scanner", capmodel.AWSResource{
		Name:         "my-bucket",
		ResourceType: "s3",
		Region:       "us-east-1",
		AccountRef:   "123456789012",
	})

	assert.Equal(t, "AWS: my-bucket", f.Title)
	assert.Equal(t, "s3", f.Location.ResourceType)
	assert.Equal(t, "us-east-1", f.Location.Region)
	assert.Equal(t, "123456789012", f.Location.AccountID)
}

func TestFromModel_GCPResource(t *testing.T) {
	f := formatter.FromModel("gcp-scanner", capmodel.GCPResource{
		Name:         "my-instance",
		ResourceType: "compute",
		Region:       "us-central1",
		AccountRef:   "my-project",
	})

	assert.Equal(t, "GCP: my-instance", f.Title)
	assert.Equal(t, "compute", f.Location.ResourceType)
	assert.Equal(t, "us-central1", f.Location.Region)
	assert.Equal(t, "my-project", f.Location.AccountID)
}

func TestFromModel_AzureResource(t *testing.T) {
	f := formatter.FromModel("azure-scanner", capmodel.AzureResource{
		Name:         "my-vm",
		ResourceType: "virtualMachine",
		Region:       "eastus",
		AccountRef:   "sub-id",
	})

	assert.Equal(t, "Azure: my-vm", f.Title)
	assert.Equal(t, "virtualMachine", f.Location.ResourceType)
	assert.Equal(t, "eastus", f.Location.Region)
	assert.Equal(t, "sub-id", f.Location.AccountID)
}

func TestFromModel_Unknown(t *testing.T) {
	f := formatter.FromModel("mystery", "just a string")

	assert.Equal(t, "Unknown model: string", f.Title)
	assert.Equal(t, formatter.SeverityInfo, f.Severity)
	assert.Equal(t, "mystery", f.Source)
}

func TestFromModel_IDGenerated(t *testing.T) {
	f := formatter.FromModel("test", capmodel.Asset{DNS: "a.com"})
	assert.NotEmpty(t, f.ID)
	assert.Contains(t, f.ID, "test-")
}

func TestFromModel_RawPreserved(t *testing.T) {
	asset := capmodel.Asset{DNS: "a.com", Name: "a"}
	f := formatter.FromModel("test", asset)

	raw, ok := f.Raw.(capmodel.Asset)
	assert.True(t, ok)
	assert.Equal(t, "a.com", raw.DNS)
}
