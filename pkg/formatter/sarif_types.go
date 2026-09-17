package formatter

// SARIF 2.1.0 types for security scan results
// Reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

const SARIFVersion = "2.1.0"
const SARIFSchema = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

// SARIFLog is the root SARIF document
type SARIFLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

// SARIFRun represents a single analysis run
type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
}

// SARIFTool describes the analysis tool
type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

// SARIFDriver describes the primary analysis tool
type SARIFDriver struct {
	Name           string       `json:"name"`
	Version        string       `json:"version,omitempty"`
	InformationURI string       `json:"informationUri,omitempty"`
	Rules          []SARIFRule  `json:"rules,omitempty"`
}

// SARIFRule describes a detection rule
type SARIFRule struct {
	ID               string           `json:"id"`
	Name             string           `json:"name,omitempty"`
	ShortDescription *SARIFMessage    `json:"shortDescription,omitempty"`
	FullDescription  *SARIFMessage    `json:"fullDescription,omitempty"`
	Help             *SARIFMessage    `json:"help,omitempty"`
	DefaultConfig    *SARIFRuleConfig `json:"defaultConfiguration,omitempty"`
	Properties       map[string]any   `json:"properties,omitempty"`
}

// SARIFRuleConfig describes rule configuration
type SARIFRuleConfig struct {
	Level string `json:"level,omitempty"` // error, warning, note, none
}

// SARIFResult represents a single finding
type SARIFResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level,omitempty"`
	Message   SARIFMessage    `json:"message"`
	Locations []SARIFLocation `json:"locations,omitempty"`
}

// SARIFMessage contains text content
type SARIFMessage struct {
	Text string `json:"text"`
}

// SARIFLocation describes where a result was found
type SARIFLocation struct {
	PhysicalLocation *SARIFPhysicalLocation `json:"physicalLocation,omitempty"`
	LogicalLocations []SARIFLogicalLocation `json:"logicalLocations,omitempty"`
}

// SARIFPhysicalLocation describes a physical file location
type SARIFPhysicalLocation struct {
	ArtifactLocation *SARIFArtifactLocation `json:"artifactLocation,omitempty"`
	Region           *SARIFRegion           `json:"region,omitempty"`
}

// SARIFArtifactLocation describes a file path
type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

// SARIFRegion describes a region within a file
type SARIFRegion struct {
	StartLine   int `json:"startLine,omitempty"`
	EndLine     int `json:"endLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
	EndColumn   int `json:"endColumn,omitempty"`
}

// SARIFLogicalLocation describes a logical location (resource, function, etc.)
type SARIFLogicalLocation struct {
	Name               string `json:"name,omitempty"`
	FullyQualifiedName string `json:"fullyQualifiedName,omitempty"`
	Kind               string `json:"kind,omitempty"`
}
