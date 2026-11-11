package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

// Without the Docker socket (plain `docker run -p`), host-published ports are still recognized via
// the container's default route; other addresses on the network stay refused.
func TestDefaultRouteGateway(t *testing.T) {
	p := filepath.Join(t.TempDir(), "route")
	// 172.17.0.1 as little-endian hex = 010011AC
	os.WriteFile(p, []byte("Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"+
		"eth0\t00000000\t010011AC\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"+
		"eth0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n"), 0o644)
	old := procNetRoute
	procNetRoute = p
	defer func() { procNetRoute = old }()

	gws := defaultRouteGateways()
	if len(gws) != 1 || !gws[0].Equal(net.ParseIP("172.17.0.1")) {
		t.Fatalf("gateways = %v", gws)
	}

	procNetRoute = filepath.Join(t.TempDir(), "missing")
	if g := defaultRouteGateways(); g != nil {
		t.Fatalf("no route file should give nothing: %v", g)
	}
}
