// Package ports is the one list of the fixed ports HardyOS's own listeners
// use, so a clash between features is caught by a test (ports_test.go)
// rather than on a server. Add every new fixed port here and refer to it
// from its package.
package ports

const (
	// AppGateway is the app gateway NetBird's reverse proxy reaches
	// (decision 112).
	AppGateway = 44200
	// Office is the office suite's own origin (editor page and Document
	// Server proxy; decision 254).
	Office = 44250
	// OfficeInternal is hardyd's listener for the Document Server container,
	// on the docker0 address (decisions 253, 266).
	OfficeInternal = 44251
	// AppProxyBase is the first app window proxy port; app n gets
	// AppProxyBase + n, up to AppProxyBase + AppProxyCount - 1 (decision 66).
	AppProxyBase  = 44300
	AppProxyCount = 100
	// Replication is the receiving side of replication (decision 190).
	Replication = 44400
)

// Fixed lists every single fixed port with its owner (the app proxy range
// is checked separately).
var Fixed = map[string]int{
	"app gateway":     AppGateway,
	"office origin":   Office,
	"office internal": OfficeInternal,
	"replication":     Replication,
}
