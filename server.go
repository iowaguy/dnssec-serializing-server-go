// The MIT License
//
// Copyright (c) 2019-2020, Cloudflare, Inc. and Apple, Inc. All rights reserved.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

const (
	// HTTP constants. Fill in your proxy and target here.
	defaultPort   = "8080"
	targetURI     = "https://dnsproxy.example.net"
	queryEndpoint = "/dns-query"

	// Environment variables
	targetNameEnvironmentVariable    = "TARGET_INSTANCE_NAME"
	experimentIDEnvironmentVariable  = "EXPERIMENT_ID"
	telemetryTypeEnvironmentVariable = "TELEMETRY_TYPE"
	certificateEnvironmentVariable   = "CERT"
	keyEnvironmentVariable           = "KEY"
)

var (
	// DNS constants. Fill in a DNS server to forward to here.
	nameServers = []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"}
)

type Server struct {
	endpoints map[string]string
	Verbose   bool
	target    *RecursiveResolver
	DOHURI    string
}

func (s Server) indexHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s Handling %s\n", r.Method, r.URL.Path)
	fmt.Fprint(w, "DNSSEC Serialization Resolver\n")
	fmt.Fprint(w, "----------------\n")
	fmt.Fprintf(w, "Endpoint: https://%s%s{?dns}\n", r.Host, s.endpoints["Target"])
	fmt.Fprint(w, "----------------\n")
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = defaultPort
	}

	var serverName string
	if serverNameSetting := os.Getenv(targetNameEnvironmentVariable); serverNameSetting != "" {
		serverName = serverNameSetting
	} else {
		serverName = "server_localhost"
	}
	log.Printf("Setting Server Name as %v", serverName)

	var experimentID string
	if experimentID = os.Getenv(experimentIDEnvironmentVariable); experimentID == "" {
		experimentID = "EXP_LOCAL"
	}

	var telemetryType string
	if telemetryType = os.Getenv(telemetryTypeEnvironmentVariable); telemetryType == "" {
		telemetryType = "LOG"
	}

	var certFile string
	if certFile = os.Getenv(certificateEnvironmentVariable); certFile == "" {
		certFile = "cert.pem"
	}

	var keyFile string
	enableTLSServe := true
	if keyFile = os.Getenv(keyEnvironmentVariable); keyFile == "" {
		keyFile = "key.pem"
		enableTLSServe = false
	}

	endpoints := make(map[string]string)
	endpoints["Target"] = queryEndpoint

	resolversInUse := make([]resolver, len(nameServers))

	for index := 0; index < len(nameServers); index++ {
		resolver := &targetResolver{
			timeout:    2500 * time.Millisecond,
			nameserver: nameServers[index],
		}
		resolversInUse[index] = resolver
	}

	target := &RecursiveResolver{
		verbose:            false,
		resolver:           resolversInUse,
		telemetryClient:    getTelemetryInstance(telemetryType),
		serverInstanceName: serverName,
		experimentId:       experimentID,
	}

	server := Server{
		endpoints: endpoints,
		target:    target,
		DOHURI:    fmt.Sprintf("%s/%s", targetURI, queryEndpoint),
	}

	http.HandleFunc(queryEndpoint, server.target.targetQueryHandler)
	http.HandleFunc("/", server.indexHandler)

	if enableTLSServe {
		log.Printf("Listening on port %v with cert %v and key %v\n", port, certFile, keyFile)
		log.Fatal(http.ListenAndServeTLS(fmt.Sprintf(":%s", port), certFile, keyFile, nil))
	} else {
		log.Printf("Listening on port %v without enabling TLS\n", port)
		log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", port), nil))
	}

}
