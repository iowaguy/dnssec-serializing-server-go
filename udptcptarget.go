package main

import (
	"fmt"
	"github.com/miekg/dns"
	"log"
	"math/rand"
	"time"
)

type UDPorTCPRecursiveResolver struct {
	verbose  bool
	resolver []resolver
}

func (s *UDPorTCPRecursiveResolver) resolveQueryWithResolver(q *dns.Msg, r resolver) ([]byte, error) {
	queryId := q.Id
	dnssecRequestedOpts := q.IsEdns0()
	dnssecRequested := false
	if dnssecRequestedOpts != nil {
		dnssecRequested = dnssecRequestedOpts.Do()
	}
	queries, err := preComputeNecessaryDNSQueries(q)

	fmt.Printf("Need to make a total of %v queries\n", len(queries))

	pStart := time.Now()
	results := ResolveParallel(queries, r)
	pEnd := time.Since(pStart)
	fmt.Printf("Time to resolve all queries: %v\n", pEnd)
	fmt.Printf("Number of resolved queries: %v\n", len(results))

	// queries contains the order of the messages to be serialized and results contains the lookup map for RR records
	requiredDNSSECRecords := make([]dns.RR, 0)
	for _, query := range queries {
		if res, ok := results[query]; ok {
			answers := res.Answer
			requiredDNSSECRecords = append(requiredDNSSECRecords, answers...)
		}
	}
	fmt.Printf("Number of required DNSSEC Records: %v\n", len(requiredDNSSECRecords))
	proof, err := makeRRsTraversable(requiredDNSSECRecords)
	if err != nil {
		fmt.Printf("proof computation failed in serialization. %v\n", err)
	}
	resp, ok := results[queries[len(queries)-1]]
	if ok {
		resp.Extra = append(resp.Extra, &proof)
	}
	// Force set response ID to match query ID for dig warnings
	resp.Id = queryId

	// Keep the server behavior consistent with a UDP based resolver
	// Perform all the necessary checks of a honest resolver and drop the signatures
	// from the final answer. Also remove the proof if dnssec has not been requested.

	if !dnssecRequested {
		answerRR := resp.Answer
		newRR := make([]dns.RR, 0)
		for _, rr := range answerRR {
			if rr.Header().Rrtype == dns.TypeRRSIG {
				continue
			}
			newRR = append(newRR, rr)
		}
		resp.Answer = newRR
		resp.Extra = make([]dns.RR, 0)
	}

	proofResponse, err := resp.Pack()

	if err != nil {
		log.Println("Failed encoding DNS response:", err)
		return nil, err
	}

	return proofResponse, err
}

// ServeDNS Attaches to the corresponding UDP Server Handler or the TCP Server Handler.
func (s *UDPorTCPRecursiveResolver) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	availableResolvers := len(s.resolver)
	chosenResolver := rand.Intn(availableResolvers)

	packedResponse, err := s.resolveQueryWithResolver(r, s.resolver[chosenResolver])
	if err != nil {
		log.Println("failed to resolve the DNS Query: ", err)
		return
	}

	_, err = w.Write(packedResponse)
	if err != nil {
		return
	}
}
