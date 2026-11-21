package main

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	plugintypes "github.com/zerelio/plugin-sdk/plugin"
	sdk "github.com/zerelio/plugin-sdk"
)

// dnsConfig holds the plugin configuration parsed from the discovery scope config.
type dnsConfig struct {
	DNSServer   string   `json:"dns_server"`
	Zone        string   `json:"zone"`
	RecordTypes []string `json:"record_types"`
}

// DNSPlugin discovers DNS zones and records.
type DNSPlugin struct {
	sdk.BasePlugin
}

var _ plugintypes.DiscoveryPlugin = (*DNSPlugin)(nil)

// recordTypeMap maps user-friendly record type names to dns type codes.
var recordTypeMap = map[string]uint16{
	"A":     dns.TypeA,
	"AAAA":  dns.TypeAAAA,
	"CNAME": dns.TypeCNAME,
	"MX":    dns.TypeMX,
	"TXT":   dns.TypeTXT,
	"NS":    dns.TypeNS,
	"SOA":   dns.TypeSOA,
	"SRV":   dns.TypeSRV,
	"PTR":   dns.TypePTR,
}

// defaultRecordTypes are the record types queried when no filter is given.
var defaultRecordTypes = []string{"A", "AAAA", "CNAME", "MX", "TXT", "NS"}

func (p *DNSPlugin) Info(ctx context.Context) (*plugintypes.PluginInfo, error) {
	return &plugintypes.PluginInfo{
		Name:        "dns",
		Version:     "1.0.0",
		Description: "DNS zone and record discovery — zone transfer and record enumeration",
		Capabilities: []string{
			"networking",
			"dns",
		},
		ConfigSchema: `{
			"type": "object",
			"properties": {
				"dns_server": {"type": "string", "description": "DNS server address (host:port, default 8.8.8.8:53)"},
				"zone": {"type": "string", "description": "DNS zone to discover (e.g. example.com)"},
				"record_types": {"type": "array", "items": {"type": "string"}, "description": "Record types to query (default: A, AAAA, CNAME, MX, TXT, NS)"}
			}
		}`,
	}, nil
}

func (p *DNSPlugin) ValidateConfig(ctx context.Context, config map[string]string) (*plugintypes.ValidationResult, error) {
	var cfg dnsConfig
	if err := sdk.ParseConfig(config, &cfg); err != nil {
		return &plugintypes.ValidationResult{Valid: false, Errors: []string{"invalid config: " + err.Error()}}, nil
	}
	// Zone is optional, but dns_server should have a valid format if provided
	if cfg.DNSServer != "" {
		if _, _, err := net.SplitHostPort(cfg.DNSServer); err != nil {
			// Allow bare IP/hostname without port
			if net.ParseIP(cfg.DNSServer) == nil && !isHostname(cfg.DNSServer) {
				return &plugintypes.ValidationResult{Valid: false, Errors: []string{fmt.Sprintf("invalid dns_server format: %s", cfg.DNSServer)}}, nil
			}
		}
	}
	return &plugintypes.ValidationResult{Valid: true}, nil
}

func (p *DNSPlugin) Discover(ctx context.Context, req *plugintypes.DiscoverRequest) (<-chan plugintypes.DiscoveryEvent, error) {
	var cfg dnsConfig
	if err := sdk.ParseConfig(req.Config, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	serverAddr := cfg.DNSServer
	if serverAddr == "" {
		serverAddr = "8.8.8.8:53"
	} else if _, _, err := net.SplitHostPort(serverAddr); err != nil {
		serverAddr = net.JoinHostPort(serverAddr, "53")
	}

	ch := make(chan plugintypes.DiscoveryEvent, 100)

	go func() {
		defer close(ch)

		zone := cfg.Zone
		if zone == "" {
			// No zone configured; just emit a progress message and return.
			ch <- sdk.SendProgress("No zone configured; specify a zone to discover DNS records", 100, 0, 0)
			return
		}

		// Ensure zone ends with a dot for FQDN
		fqdn := dns.Fqdn(zone)

		// Discover nameservers for the zone
		nameservers := discoverNameservers(ctx, serverAddr, fqdn)

		// Emit zone resource
		zoneID := fmt.Sprintf("dns:zone:%s", zone)
		zr := sdk.NewResource( "dns", "dns.zone", "global", zone, zone)
		zr.ID = zoneID
		zr.Properties = map[string]string{
			"name":        zone,
			"nameservers": strings.Join(nameservers, ", "),
		}
		zr.RawData = sdk.MarshalRawData(map[string]interface{}{
			"name":        zone,
			"nameservers": nameservers,
		})
		sdk.EmitResource(ch, zr)

		ch <- sdk.SendProgress(fmt.Sprintf("Zone %s discovered", zone), 20, 1, 0)
		if ctx.Err() != nil {
			return
		}

		// Try AXFR zone transfer first
		axfrRecords, axfrErr := attemptAXFR(ctx, serverAddr, fqdn)
		if axfrErr == nil && len(axfrRecords) > 0 {
			// Use AXFR results
			recordCount := 0
			for _, rr := range axfrRecords {
				emitDNSRecord(ch, zoneID, zone, rr)
				recordCount++
			}
			ch <- sdk.SendProgress(fmt.Sprintf("Zone transfer complete: %d records", recordCount), 100, 0, 0)
			return
		}

		// AXFR failed or unavailable; fall back to individual lookups
		types := cfg.RecordTypes
		if len(types) == 0 {
			types = defaultRecordTypes
		}

		totalTypes := len(types)
		for i, rt := range types {
			if ctx.Err() != nil {
				return
			}

			qtype, ok := recordTypeMap[strings.ToUpper(rt)]
			if !ok {
				ch <- sdk.SendError("INVALID_RECORD_TYPE", fmt.Sprintf("unsupported record type: %s", rt), false)
				continue
			}

			records, err := queryRecords(ctx, serverAddr, fqdn, qtype)
			if err != nil {
				ch <- sdk.SendError("QUERY_ERROR", fmt.Sprintf("failed to query %s records for %s: %s", rt, zone, err), false)
				continue
			}

			for _, rr := range records {
				emitDNSRecord(ch, zoneID, zone, rr)
			}

			pct := 20 + int(float64(i+1)/float64(totalTypes)*80)
			ch <- sdk.SendProgress(fmt.Sprintf("%s records queried", rt), int32(pct), 0, 0)
		}
	}()

	return ch, nil
}

// ─── DNS Helpers ───────────────────────────────────────────────────────────

// discoverNameservers looks up NS records for the given zone.
func discoverNameservers(ctx context.Context, serverAddr, fqdn string) []string {
	client := &dns.Client{Timeout: 10 * time.Second}
	m := new(dns.Msg)
	m.SetQuestion(fqdn, dns.TypeNS)

	r, _, err := client.Exchange(m, serverAddr)
	if err != nil || r == nil {
		return nil
	}

	var ns []string
	for _, ans := range r.Answer {
		if nsRR, ok := ans.(*dns.NS); ok {
			ns = append(ns, nsRR.Ns)
		}
	}
	return ns
}

// attemptAXFR tries a zone transfer (AXFR) for the given zone.
func attemptAXFR(ctx context.Context, serverAddr, fqdn string) ([]dns.RR, error) {
	transfer := &dns.Transfer{
		DialTimeout: 10 * time.Second,
	}

	m := new(dns.Msg)
	m.SetAxfr(fqdn)

	envCh, err := transfer.In(m, serverAddr)
	if err != nil {
		return nil, err
	}

	var all []dns.RR
	for env := range envCh {
		if env.Error != nil {
			return nil, env.Error
		}
		all = append(all, env.RR...)
	}

	if len(all) == 0 {
		return nil, fmt.Errorf("no records returned from AXFR")
	}

	return all, nil
}

// queryRecords performs a DNS lookup for a specific record type.
func queryRecords(ctx context.Context, serverAddr, fqdn string, qtype uint16) ([]dns.RR, error) {
	client := &dns.Client{Timeout: 10 * time.Second}
	m := new(dns.Msg)
	m.SetQuestion(fqdn, qtype)

	r, _, err := client.Exchange(m, serverAddr)
	if err != nil {
		return nil, err
	}

	if r == nil || len(r.Answer) == 0 {
		return nil, nil
	}

	return r.Answer, nil
}

// emitDNSRecord creates and sends a DNS record resource event.
func emitDNSRecord(ch chan<- plugintypes.DiscoveryEvent, zoneID, zone string, rr dns.RR) {
	header := rr.Header()
	recordName := strings.TrimSuffix(header.Name, ".")
	recordType := dns.TypeToString[header.Rrtype]
	if recordType == "" {
		recordType = fmt.Sprintf("TYPE%d", header.Rrtype)
	}

	value := extractRecordValue(rr)
	recordID := fmt.Sprintf("dns:record:%s:%s:%s", zone, recordType, recordName)

	res := sdk.NewResource("dns", "dns.record", "global", zone, fmt.Sprintf("%s %s", recordName, recordType))
	res.ID = recordID
	res.Properties = map[string]string{
		"name":  recordName,
		"type":  recordType,
		"value": value,
		"ttl":   strconv.Itoa(int(header.Ttl)),
	}
	res.RawData = sdk.MarshalRawData(map[string]interface{}{
		"name":  recordName,
		"type":  recordType,
		"value": value,
		"ttl":   header.Ttl,
	})
	sdk.EmitResource(ch, res)

	// Record belongs to zone
	sdk.EmitRelationship(ch, sdk.NewRelationship(recordID, zoneID, "BELONGS_TO"))
}

// extractRecordValue gets the string value from a DNS resource record.
func extractRecordValue(rr dns.RR) string {
	switch v := rr.(type) {
	case *dns.A:
		return v.A.String()
	case *dns.AAAA:
		return v.AAAA.String()
	case *dns.CNAME:
		return strings.TrimSuffix(v.Target, ".")
	case *dns.MX:
		return fmt.Sprintf("%d %s", v.Preference, strings.TrimSuffix(v.Mx, "."))
	case *dns.TXT:
		return strings.Join(v.Txt, " ")
	case *dns.NS:
		return strings.TrimSuffix(v.Ns, ".")
	case *dns.SOA:
		return fmt.Sprintf("%s %s", strings.TrimSuffix(v.Ns, "."), strings.TrimSuffix(v.Mbox, "."))
	case *dns.SRV:
		return fmt.Sprintf("%d %d %d %s", v.Priority, v.Weight, v.Port, strings.TrimSuffix(v.Target, "."))
	case *dns.PTR:
		return strings.TrimSuffix(v.Ptr, ".")
	default:
		return rr.String()
	}
}

// isHostname does a basic check if s looks like a hostname.
func isHostname(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, part := range strings.Split(s, ".") {
		if len(part) == 0 {
			return false
		}
		for _, c := range part {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}
