package aerospike

import (
	"net"
	"strconv"
)

// defaultPort is the Aerospike service port used when a host has no explicit
// port.
const defaultPort = 3000

// splitHostPort parses "host:port" or bare "host" into (host, port). A bare
// host defaults to defaultPort.
func splitHostPort(hp string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(hp)
	if err != nil {
		// No port present: treat the whole string as the host.
		return hp, defaultPort, nil
	}
	port, perr := strconv.Atoi(portStr)
	if perr != nil {
		return "", 0, perr
	}
	return host, port, nil
}
