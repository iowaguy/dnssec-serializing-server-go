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
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"strings"
	"time"
)

type RecursiveResolver struct {
	verbose            bool
	resolver           []resolver
	telemetryClient    *telemetry
	serverInstanceName string
	experimentId       string
}

type zoneData struct {
	zoneName  string
	dnskeyRRs []dns.RR
	dsRRs     []dns.RR
}

func (z zoneData) String() string {
	builder := strings.Builder{}
	builder.WriteString(z.zoneName)
	builder.WriteString("\n")
	for _, key := range z.dnskeyRRs {
		builder.WriteString(key.String())
		builder.WriteString("\n")
	}
	for _, ds := range z.dsRRs {
		builder.WriteString(ds.String())
		builder.WriteString("\n")
	}
	return builder.String()
}

type zoneStack []zoneData

func (s zoneStack) isEmpty() bool {
	return len(s) == 0
}

func (s zoneStack) push(v zoneData) zoneStack {
	return append(s, v)
}

func (s zoneStack) pop() (zoneStack, zoneData) {
	if s.isEmpty() {
		return s, zoneData{}
	} else {
		l := len(s)
		return s[:l-1], s[l-1]
	}
}

func (s zoneStack) collect() []dns.RR {
	rrs := make([]dns.RR, 0)
	for _, z := range s {
		rrs = append(rrs, z.dnskeyRRs...)
		rrs = append(rrs, z.dsRRs...)
	}

	return rrs
}

func (s zoneStack) String() string {
	builder := strings.Builder{}

	for _, z := range s {
		builder.WriteString(z.String())
	}
	return builder.String()
}

const (
	dnsMessageContentType = "application/dns-message"
)

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// This function calculates the zone depth of the longest common suffix
func calcNewDepth(currentDomain, targetDomain string) (int, error) {
	for i := 0; i < 256; i++ {
		idxCurrent, startCurrent := dns.PrevLabel(currentDomain, i)
		idxTarget, startTarget := dns.PrevLabel(targetDomain, i)
		if startCurrent || startTarget || currentDomain[idxCurrent:] != targetDomain[idxTarget:] {
			return i, nil
		}
	}

	return 0, errors.New("Domains exceed the max length.")
}

func decodeDNSQuestion(encodedMessage []byte) (*dns.Msg, error) {
	msg := &dns.Msg{}
	err := msg.Unpack(encodedMessage)
	return msg, err
}

func (s *RecursiveResolver) parseQueryFromRequest(r *http.Request) (*dns.Msg, error) {
	switch r.Method {
	case http.MethodGet:
		var queryBody string
		if queryBody = r.URL.Query().Get("dns"); queryBody == "" {
			return nil, fmt.Errorf("Missing DNS query parameter in GET request")
		}

		encodedMessage, err := base64.RawURLEncoding.DecodeString(queryBody)
		if err != nil {
			return nil, err
		}

		return decodeDNSQuestion(encodedMessage)
	case http.MethodPost:
		if r.Header.Get("Content-Type") != dnsMessageContentType {
			return nil, fmt.Errorf("incorrect content type, expected '%s', got %s", dnsMessageContentType, r.Header.Get("Content-Type"))
		}

		defer r.Body.Close()
		encodedMessage, err := ioutil.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}

		return decodeDNSQuestion(encodedMessage)
	default:
		return nil, fmt.Errorf("unsupported HTTP method")
	}
}

func isSignedByParent(domainName string, rrs []dns.RR) bool {
	segments := strings.Split(domainName, ".")
	numberSegments := len(segments)
	// fail fast
	if numberSegments < 0 {
		return false
	}
	parentDomain := strings.Join(segments[1:], ".")
	for _, rrRecord := range rrs {
		switch rrRecord.(type) {
		case *dns.RRSIG:
			t := (rrRecord).(*dns.RRSIG)
			if t.SignerName == parentDomain &&
				t.TypeCovered == dns.TypeNSEC || t.TypeCovered == dns.TypeNSEC3 || t.TypeCovered == dns.TypeSOA {
				return true
			}
		}
	}
	return false
}

func (s *RecursiveResolver) fetchSingleDnssecRecord(domainName string, r resolver, qtype uint16) ([]dns.RR, error) {
	dnsQuery := new(dns.Msg)
	dnsQuery.SetQuestion(dns.Fqdn(domainName), qtype)
	dnsQuery.SetEdns0(4096, true)

	packedDnsQuery, err := dnsQuery.Pack()
	if err != nil {
		log.Println("Failed encoding DNS query:", err)
		return nil, err
	}

	if s.verbose {
		log.Printf("Query=%s\n", packedDnsQuery)
	}

	start := time.Now()
	response, err := r.resolve(dnsQuery)
	if err != nil {
		log.Println("Failed to resolve query:", err)
		return nil, err
	}
	elapsed := time.Since(start)

	// For proofs of nonexistence point to the Next Secure record (NSEC) which is in the Authority section.
	//fmt.Printf("Response: %v\n", response)
	if len(response.Answer) == 0 && !isSignedByParent(dns.Fqdn(domainName), response.Ns) {
		return response.Ns, nil
	}

	packedResponse, err := response.Pack()
	if err != nil {
		log.Println("Failed encoding DNS response:", err)
		return nil, err
	}

	if s.verbose {
		log.Printf("Answer=%s elapsed=%s\n", packedResponse, elapsed.String())
	}

	return response.Answer, err
}

func (s *RecursiveResolver) fetchDnskeyRecord(domainName string, r resolver) ([]dns.RR, error) {
	return s.fetchSingleDnssecRecord(domainName, r, dns.TypeDNSKEY)
}

func (s *RecursiveResolver) fetchDsRecord(domainName string, r resolver) ([]dns.RR, error) {
	return s.fetchSingleDnssecRecord(domainName, r, dns.TypeDS)
}

func containsCNAME(rrs []dns.RR) (*dns.CNAME, bool) {
	for _, rr := range rrs {
		switch rr.(type) {
		case *dns.CNAME:
			return rr.(*dns.CNAME), true
		}
	}
	return nil, false
}

func (s *RecursiveResolver) getZoneRRs(targetDomain []string, depth int, r resolver) ([]dns.RR, error) {
	if depth == -1 {
		return make([]dns.RR, 0), nil
	}
	currentZone := dns.Fqdn(strings.Join(targetDomain[depth:], "."))
	fmt.Printf("[%v] Querying %v\n", depth, currentZone)

	dnskeyRRs, err := s.fetchDnskeyRecord(currentZone, r)
	if err != nil {
		fmt.Printf("%v Failed to fetch DNSKEY Records.", currentZone)
		return nil, err
	}

	var dsRRs []dns.RR
	if currentZone != "." {
		dsRRs, err = s.fetchDsRecord(currentZone, r)
		if err != nil {
			fmt.Printf("%v Failed to fetch DS Records.", currentZone)
			return nil, err
		}

	}

	zs, err := s.getZoneRRs(targetDomain, depth-1, r)
	if err != nil {
		return nil, err
	}

	return append(append(dnskeyRRs, dsRRs...), zs...), nil
}

func (s *RecursiveResolver) fetchDnssecRecords(targetDomain string, answer []dns.RR, r resolver) ([]dns.RR, error) {
	zones := append(dns.SplitDomainName(targetDomain), "")
	rrs, err := s.getZoneRRs(zones, len(zones)-1, r)
	if err != nil {
		fmt.Printf("Failed to fetch DNSSEC Records, error: %v\n", err)
		return nil, err
	}

	return append(rrs, answer...), nil
}

// Check if the provided key is a key-signing key
func checkIfKSK(key *dns.DNSKEY) bool {
	// is zone key
	isKey := 0 != key.Flags&dns.ZONE

	// is Secure Entry Point
	isSEP := 0 != key.Flags&dns.SEP

	return isKey && isSEP
}

func convertDnskeyToKey(dnskey *dns.DNSKEY) dns.Key {
	//fmt.Printf("Received DNSKEY: %v\n", dnskey.String())
	k := dns.Key{
		Flags:      dnskey.Flags,
		Protocol:   dnskey.Protocol,
		Algorithm:  dnskey.Algorithm,
		Public_key: []byte(dnskey.PublicKey),
	}
	k.Length = uint16(dns.Len(&k))
	return k
}

func convertDsToSerialDs(ds *dns.DS) dns.SerialDS {
	s := dns.SerialDS{
		Key_tag:     ds.KeyTag,
		Algorithm:   ds.Algorithm,
		Digest_type: ds.DigestType,
		Digest:      []byte(ds.Digest),
	}
	s.Digest_len = uint16(len(s.Digest))
	s.Length = uint16(dns.Len(&s))
	return s
}

func convertRrsigToSignature(rrsig *dns.RRSIG) dns.Signature {
	s := dns.Signature{
		Algorithm:  rrsig.Algorithm,
		Labels:     rrsig.Labels,
		Ttl:        rrsig.OrigTtl,
		Expires:    rrsig.Expiration,
		Begins:     rrsig.Inception,
		Key_tag:    rrsig.KeyTag,
		SignerName: rrsig.SignerName,
		Signature:  []byte(rrsig.Signature),
	}
	s.Length = uint16(dns.Len(&s))
	return s
}

// The input resource records are already in canonical order
func makeRRsTraversable(rrs []dns.RR) (dns.DNSSECProof, error) {
	zones := make([]dns.ZonePair, 0)
	zoneName := ""
	currentEntry := &dns.Entering{
		ZType: dns.EnteringType,
		Keys:  make([]dns.Key, 0),
	}
	currentExit := &dns.Leaving{
		ZType:       dns.LeavingType,
		LeavingType: dns.LeavingUncommitted,
	}
	leafAdded := false

	for _, v := range rrs {
		fmt.Printf("\u001B[32m %v \u001B[0m\n", v.String())
		// set the zone name for the first zone we're traversing
		if zoneName == "" {
			zoneName = v.Header().Name
		}

		// check if this record is part of a new zone
		if v.Header().Name != zoneName {
			zoneName = v.Header().Name

			// populate the remaining fields from the previous zone
			currentEntry.Num_keys = uint8(len(currentEntry.Keys))
			currentEntry.Length = uint16(dns.Len(currentEntry))
			currentExit.Next_name = dns.Name(v.Header().Name)
			currentExit.Length = uint16(dns.Len(currentExit))

			// append previous zone's entries to struct
			zp := dns.ZonePair{
				Entry: *currentEntry,
				Exit:  *currentExit,
			}
			zones = append(zones, zp)

			// create new entry and exit for the new current zone
			currentEntry = &dns.Entering{
				ZType: dns.EnteringType,
				Keys:  make([]dns.Key, 0),
			}
			currentExit = &dns.Leaving{
				ZType:       dns.LeavingType,
				LeavingType: dns.LeavingUncommitted,
			}
		}

		// still reading records from the same zone
		switch t := v.(type) {
		case *dns.DNSKEY:
			if checkIfKSK(t) {
				currentEntry.Entry_key_index = uint8(len(currentEntry.Keys))
			}

			key := convertDnskeyToKey(t)
			currentEntry.Keys = append(currentEntry.Keys, key)
		case *dns.DS:
			ds := convertDsToSerialDs(t)

			if len(zones) == 0 {
				return dns.DNSSECProof{}, errors.New("Root zone cannot have a DS record")
			}

			if l := zones[len(zones)-1].Exit; l.LeavingType == dns.LeavingUncommitted {
				l.LeavingType = dns.LeavingDSType
				l.Ds_records = make([]dns.SerialDS, 0)
				l.Ds_records = append(l.Ds_records, ds)
				l.Num_ds = uint8(len(l.Ds_records))
				l.Rrtype = dns.RRType(dns.TypeDS)
				zones[len(zones)-1].Exit = l
			} else if l.LeavingType == dns.LeavingDSType {
				l.Ds_records = append(l.Ds_records, ds)
				l.Num_ds = uint8(len(l.Ds_records))
				zones[len(zones)-1].Exit = l
			} else {
				return dns.DNSSECProof{}, errors.New("Exit struct already has non-DS type")
			}

			// update the struct length after modifications
			zones[len(zones)-1].Exit.Length = uint16(dns.Len(&zones[len(zones)-1].Exit))
		case *dns.RRSIG:
			switch t.TypeCovered {
			case dns.TypeDNSKEY:
				currentEntry.Key_sig = convertRrsigToSignature(t)
			case dns.TypeDS:
				if len(zones) == 0 {
					return dns.DNSSECProof{}, errors.New("Root zone cannot have a DS record")
				}

				if zones[len(zones)-1].Exit.LeavingType == dns.LeavingUncommitted {
					return dns.DNSSECProof{}, errors.New("Should have seen a DS record before this signature")
				} else if zones[len(zones)-1].Exit.LeavingType == dns.LeavingDSType {
					zones[len(zones)-1].Exit.Rrsig = convertRrsigToSignature(t)
				} else {
					return dns.DNSSECProof{}, errors.New("Exit struct already has non-DS type")
				}

				// update the struct length after modifications
				zones[len(zones)-1].Exit.Length = uint16(dns.Len(&zones[len(zones)-1].Exit))
			default:
				if leafAdded {
					signerName := t.SignerName
					zName := t.Hdr.Name
					parentZName := dns.Fqdn(strings.Join(dns.SplitDomainName(zName)[1:], "."))
					if signerName == parentZName {
						// Lookup the keys for the signer
						currentEntry = &zones[len(zones)-1].Entry
						zones[len(zones)-1].Exit.LeavingType = dns.LeavingOtherType
						zones[len(zones)-1].Exit.Length = uint16(dns.Len(&zones[len(zones)-1].Exit))
					}
				}
				currentExit.Rrsig = convertRrsigToSignature(t)
				currentExit.Rrtype = dns.RRType(t.TypeCovered)
			}

		case *dns.DNAME:
			return dns.DNSSECProof{}, errors.New("DNAME is not supported")
		case *dns.CNAME:
			return dns.DNSSECProof{}, errors.New("CNAME is not supported")
		case *dns.A, *dns.TXT, *dns.AAAA:
			leafAdded = true
			addLeafRR(currentExit, v)
		default:
			return dns.DNSSECProof{}, errors.New("Type " + t.String() + " is not supported")
		}
	}

	// populate the remaining fields from the previous zone
	currentEntry.Length = uint16(dns.Len(currentEntry))
	currentEntry.Num_keys = uint8(len(currentEntry.Keys))

	// the final exit won't contain any data, just need to
	// do some record keeping
	currentExit.Rrsig.Length = uint16(dns.Len(&currentExit.Rrsig))
	currentExit.Length = uint16(dns.Len(currentExit))
	currentExit.Next_name = dns.Name(zoneName)

	// append previous zone's entries to struct
	zp := dns.ZonePair{
		Entry: *currentEntry,
		Exit:  *currentExit,
	}
	zones = append(zones, zp)

	return dns.DNSSECProof{
		Hdr: dns.RR_Header{
			Name:   zoneName,
			Rrtype: dns.TypeDNSSECProof,
		},
		// NOTE zero indicates that we're using the root zone's key-signing key
		Initial_key_tag: 0,
		Num_zones:       uint8(len(zones)),
		Zones:           zones,
	}, nil
}

func addLeafRR(exit *dns.Leaving, rr dns.RR) {
	exit.LeavingType = dns.LeavingOtherType

	if exit.Rrs == nil {
		exit.Rrs = make([]dns.RR, 0)
	}
	exit.Rrs = append(exit.Rrs, rr)
	exit.Num_rrs = uint8(len(exit.Rrs))
}

func (s *RecursiveResolver) resolveQueryWithResolver(q *dns.Msg, r resolver) ([]byte, error) {

	packedQuery, err := q.Pack()
	if err != nil {
		log.Println("Failed encoding DNS query:", err)
		return nil, err
	}

	if s.verbose {
		log.Printf("Query=%s\n", packedQuery)
	}

	start := time.Now()
	response, err := r.resolve(q)
	elapsed := time.Since(start)

	var dnssecProof dns.DNSSECProof
	if q.IsEdns0().Do() {
		allDNSSECRecords, err := s.fetchDnssecRecords(q.Question[0].Name, response.Answer, r)
		if err != nil {
			log.Println("Failed retrieving DNSSEC proofs:", err)
			return nil, err
		}
		dnssecProof, err = makeRRsTraversable(allDNSSECRecords)
		if err != nil {
			log.Println("Failed serializing DNSSEC proofs:", err)
			// Return the non DNSSEC serialized DNS response as fail-over
			return response.Pack()
		}

		response.Extra = append(response.Extra, &dnssecProof)

		b, _ := response.Pack()
		fmt.Printf("Response Size : %v\n", len(b))
	}

	packedResponse, err := response.Pack()
	if err != nil {
		log.Println("Failed encoding DNS response:", err)
		return nil, err
	}

	if s.verbose {
		log.Printf("Answer=%s elapsed=%s\n", packedResponse, elapsed.String())
	}

	return packedResponse, err
}

func (s *RecursiveResolver) dohQueryHandler(w http.ResponseWriter, r *http.Request) {
	requestReceivedTime := time.Now()
	exp := experiment{}
	exp.ExperimentID = s.experimentId
	exp.IngestedFrom = s.serverInstanceName
	exp.ProtocolType = "ClearText-ODOH"
	exp.RequestID = nil
	timestamp := runningTime{}

	timestamp.Start = requestReceivedTime.UnixNano()
	query, err := s.parseQueryFromRequest(r)
	if err != nil {
		log.Println("Failed parsing request:", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	timestamp.TargetQueryDecryptionTime = time.Now().UnixNano()

	availableResolvers := len(s.resolver)
	chosenResolver := rand.Intn(availableResolvers)
	packedResponse, err := s.resolveQueryWithResolver(query, s.resolver[chosenResolver])
	if err != nil {
		log.Println("Failed resolving DNS query:", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	endTime := time.Now().UnixNano()
	timestamp.TargetQueryResolutionTime = endTime
	timestamp.TargetAnswerEncryptionTime = endTime
	timestamp.EndTime = endTime

	exp.Timestamp = timestamp
	exp.Resolver = s.resolver[chosenResolver].name()
	exp.Status = true

	if s.telemetryClient.logClient != nil {
		go s.telemetryClient.streamTelemetryToGCPLogging([]string{exp.serialize()})
	} else if s.telemetryClient.esClient != nil {
		go s.telemetryClient.streamDataToElastic([]string{exp.serialize()})
	}

	w.Header().Set("Content-Type", dnsMessageContentType)
	w.Write(packedResponse)
}

func (s *RecursiveResolver) targetQueryHandler(w http.ResponseWriter, r *http.Request) {
	if s.verbose {
		log.Printf("%s Handling %s\n", r.Method, r.URL.Path)
		log.Printf("Header: %v\n", r.Header.Get("Content-Type"))
	}

	if r.Header.Get("Content-Type") == dnsMessageContentType {
		s.dohQueryHandler(w, r)
	} else {
		log.Printf("Invalid content type: %s", r.Header.Get("Content-Type"))
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
	}
}
