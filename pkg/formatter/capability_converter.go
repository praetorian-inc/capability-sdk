package formatter

import (
	"fmt"
	"time"

	"github.com/praetorian-inc/capability-sdk/pkg/capmodel"
)

// riskTargetHost extracts a host identifier from a Risk's polymorphic target.
func riskTargetHost(target any) string {
	switch t := target.(type) {
	case capmodel.Asset:
		return t.DNS
	case *capmodel.Asset:
		return t.DNS
	case capmodel.Repository:
		return t.URL
	case *capmodel.Repository:
		return t.URL
	default:
		return ""
	}
}

// FromModel converts a capmodel type emitted by a capability into a
// formatter.Finding. The source parameter identifies the capability
// that produced the model (e.g. "subdomain-scanner").
func FromModel(source string, model any) Finding {
	f := Finding{
		Source:    source,
		Timestamp: time.Now(),
		Metadata:  make(map[string]any),
		Raw:       model,
	}

	switch m := model.(type) {
	case capmodel.Risk:
		f.Title = m.Name
		f.Source = source
		f.Location.Host = riskTargetHost(m.Target)
		f.Metadata["status"] = m.Status

	case *capmodel.Risk:
		f.Title = m.Name
		f.Source = source
		f.Location.Host = riskTargetHost(m.Target)
		f.Metadata["status"] = m.Status

	case capmodel.Asset:
		f.Title = fmt.Sprintf("Asset: %s", m.DNS)
		f.Severity = SeverityInfo
		f.Location.Host = m.DNS
		f.Metadata["name"] = m.Name

	case *capmodel.Asset:
		f.Title = fmt.Sprintf("Asset: %s", m.DNS)
		f.Severity = SeverityInfo
		f.Location.Host = m.DNS
		f.Metadata["name"] = m.Name

	case capmodel.Domain:
		f.Title = fmt.Sprintf("Domain: %s", m.Domain)
		f.Severity = SeverityInfo
		f.Location.Host = m.Domain

	case *capmodel.Domain:
		f.Title = fmt.Sprintf("Domain: %s", m.Domain)
		f.Severity = SeverityInfo
		f.Location.Host = m.Domain

	case capmodel.IP:
		f.Title = fmt.Sprintf("IP: %s", m.IP)
		f.Severity = SeverityInfo
		f.Location.Host = m.IP

	case *capmodel.IP:
		f.Title = fmt.Sprintf("IP: %s", m.IP)
		f.Severity = SeverityInfo
		f.Location.Host = m.IP

	case capmodel.Port:
		f.Title = fmt.Sprintf("Port: %d/%s", m.Port, m.Protocol)
		f.Severity = SeverityInfo
		f.Location.Port = m.Port
		f.Location.Protocol = m.Protocol
		f.Location.Host = m.Parent.DNS
		f.Metadata["service"] = m.Service

	case *capmodel.Port:
		f.Title = fmt.Sprintf("Port: %d/%s", m.Port, m.Protocol)
		f.Severity = SeverityInfo
		f.Location.Port = m.Port
		f.Location.Protocol = m.Protocol
		f.Location.Host = m.Parent.DNS
		f.Metadata["service"] = m.Service

	case capmodel.WebApplication:
		f.Title = fmt.Sprintf("WebApp: %s", m.Name)
		f.Severity = SeverityInfo
		f.Location.URL = m.PrimaryURL
		f.Metadata["name"] = m.Name

	case *capmodel.WebApplication:
		f.Title = fmt.Sprintf("WebApp: %s", m.Name)
		f.Severity = SeverityInfo
		f.Location.URL = m.PrimaryURL
		f.Metadata["name"] = m.Name

	case capmodel.Webpage:
		f.Title = fmt.Sprintf("Webpage: %s", m.URL)
		f.Severity = SeverityInfo
		f.Location.URL = m.URL

	case *capmodel.Webpage:
		f.Title = fmt.Sprintf("Webpage: %s", m.URL)
		f.Severity = SeverityInfo
		f.Location.URL = m.URL

	case capmodel.AWSResource:
		f.Title = fmt.Sprintf("AWS: %s", m.Name)
		f.Severity = SeverityInfo
		f.Location.ResourceType = m.ResourceType
		f.Location.Region = m.Region
		f.Location.AccountID = m.AccountRef

	case *capmodel.AWSResource:
		f.Title = fmt.Sprintf("AWS: %s", m.Name)
		f.Severity = SeverityInfo
		f.Location.ResourceType = m.ResourceType
		f.Location.Region = m.Region
		f.Location.AccountID = m.AccountRef

	case capmodel.GCPResource:
		f.Title = fmt.Sprintf("GCP: %s", m.Name)
		f.Severity = SeverityInfo
		f.Location.ResourceType = m.ResourceType
		f.Location.Region = m.Region
		f.Location.AccountID = m.AccountRef

	case *capmodel.GCPResource:
		f.Title = fmt.Sprintf("GCP: %s", m.Name)
		f.Severity = SeverityInfo
		f.Location.ResourceType = m.ResourceType
		f.Location.Region = m.Region
		f.Location.AccountID = m.AccountRef

	case capmodel.AzureResource:
		f.Title = fmt.Sprintf("Azure: %s", m.Name)
		f.Severity = SeverityInfo
		f.Location.ResourceType = m.ResourceType
		f.Location.Region = m.Region
		f.Location.AccountID = m.AccountRef

	case *capmodel.AzureResource:
		f.Title = fmt.Sprintf("Azure: %s", m.Name)
		f.Severity = SeverityInfo
		f.Location.ResourceType = m.ResourceType
		f.Location.Region = m.Region
		f.Location.AccountID = m.AccountRef

	default:
		f.Title = fmt.Sprintf("Unknown model: %T", model)
		f.Severity = SeverityInfo
	}

	if f.ID == "" {
		f.ID = fmt.Sprintf("%s-%d", source, time.Now().UnixNano())
	}

	return f
}
