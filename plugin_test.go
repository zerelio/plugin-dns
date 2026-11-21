package main

import (
	"context"
	"testing"
)

func TestDNSPlugin_ValidateConfig_Valid(t *testing.T) {
	p := &DNSPlugin{}
	r, err := p.ValidateConfig(context.Background(), map[string]string{})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Valid {
		t.Fatal("expected valid for empty config (all fields optional)")
	}
}

func TestDNSPlugin_ValidateConfig_InvalidServer(t *testing.T) {
	p := &DNSPlugin{}
	r, err := p.ValidateConfig(context.Background(), map[string]string{
		"dns_server": "not-a-valid-host!!!",
	})
	if err != nil {
		t.Fatal(err)
	}
	if r.Valid {
		t.Fatal("expected invalid for bad dns_server")
	}
}

func TestDNSPlugin_Info(t *testing.T) {
	p := &DNSPlugin{}
	info, err := p.Info(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if info.Name != "dns" {
		t.Fatalf("expected dns, got %s", info.Name)
	}
}
