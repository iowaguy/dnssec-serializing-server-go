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
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"strings"
	"time"

	odoh "github.com/cloudflare/odoh-go"
	"github.com/miekg/dns"
)

type targetServer struct {
	verbose            bool
	resolver           []resolver
	odohKeyPair        odoh.ObliviousDoHKeyPair
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
	dnsMessageContentType  = "application/dns-message"
	odohMessageContentType = "application/oblivious-dns-message"
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

func (s *targetServer) parseQueryFromRequest(r *http.Request) (*dns.Msg, error) {
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

func (s *targetServer) fetchSingleDnssecRecord(domainName string, r resolver, qtype uint16) ([]dns.RR, error) {
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

func (s *targetServer) fetchDnskeyRecord(domainName string, r resolver) ([]dns.RR, error) {
	return s.fetchSingleDnssecRecord(domainName, r, dns.TypeDNSKEY)
}

func (s *targetServer) fetchDsRecord(domainName string, r resolver) ([]dns.RR, error) {
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

func (s *targetServer) getZoneRRs(targetDomain []string, depth int, r resolver) ([]dns.RR, error) {
	if depth == -1 {
		return make([]dns.RR, 0), nil
	}
	currentZone := dns.Fqdn(strings.Join(targetDomain[depth:], "."))

	dnskeyRRs, err := s.fetchDnskeyRecord(currentZone, r)
	if err != nil {
		return nil, err
	}

	var dsRRs []dns.RR
	if currentZone != "." {
		dsRRs, err = s.fetchDsRecord(currentZone, r)
		if err != nil {
			return nil, err
		}

	}

	zs, err := s.getZoneRRs(targetDomain, depth-1, r)
	if err != nil {
		return nil, err
	}

	return append(append(dnskeyRRs, dsRRs...), zs...), nil
}

// func (s *targetServer) getZoneRecords(currentZone string, r resolver) ([]dns.RR, error) {
// 	currentZone = dns.Fqdn(currentZone)

// 	// zone := zoneData{
// 	// 	zoneName: currentZone,
// 	// }

// 	// Request DNSKEYs and RRSIG DNSKEYs for the current zone
// 	dnskeyRRs, err := s.fetchDnskeyRecord(currentZone, r)
// 	if err != nil {
// 		return nil, err
// 	}
// 	// zone.dnskeyRRs = append(zone.dnskeyRRs, dnskeyRRs...)

// 	// If current zone != ".", request DS and RRSIG DS for current zone.
// 	var dsRRs []dns.RR
// 	if currentZone != "." {
// 		dsRRs, err = s.fetchDsRecord(currentZone, r)
// 		if err != nil {
// 			return nil, err
// 		}
// 		// zone.dsRRs = append(zone.dsRRs, dsRRs...)
// 	}

// 	return append(dnskeyRRs, dsRRs...), nil
// }

func (s *targetServer) fetchDnssecRecords(targetDomain string, answer []dns.RR, r resolver) ([]dns.RR, error) {
	// Initialize empty stack
	// stack := make(zoneStack, 0)
	zones := append(dns.SplitDomainName(targetDomain), "")

	rrs, err := s.getZoneRRs(zones, len(zones)-1, r)
	if err != nil {
		return nil, err
	}

	return append(rrs, answer...), nil

	// 2) Iterate down zone hierarchy starting at root
	// for i := len(zones) - 1; i >= 0; i-- {
	// 	currentZone := dns.Fqdn(strings.Join(zones[i:], "."))

	// 	zone, err := s.getZoneRecords(currentZone, r)
	// 	if err != nil {
	// 		return nil, err
	// 	}

	// 	stack = stack.push(zone)

	// 	// If r contains a CNAME, replace the target with the one referenced in the
	// 	// CNAME. Then return up the stack for each zone until the new target is
	// 	// within the current zone.
	// 	if cname, isCNAME := containsCNAME(zone.dnskeyRRs); isCNAME {
	// 		targetDomain = cname.Target
	// 		newDepth, err := calcNewDepth(currentZone, targetDomain)
	// 		if err != nil {
	// 			return nil, err
	// 		}

	// 		zones = append(dns.SplitDomainName(targetDomain), "")
	// 		for j := newDepth - 1; j >= 0; j-- {
	// 			currentZone := dns.Fqdn(strings.Join(zones[j:], "."))

	// 			// Request DNSKEYs and RRSIG DNSKEYs for the current zone
	// 			dnskeyRRs, err := s.fetchDnskeyRecord(currentZone, r)
	// 			if err != nil {
	// 				return nil, err
	// 			}

	// 			zone := zoneData{
	// 				zoneName: currentZone,
	// 			}

	// 			zone.dnskeyRRs = append(zone.dnskeyRRs, dnskeyRRs...)

	// 			dsRRs, err := s.fetchDsRecord(currentZone, r)
	// 			if err != nil {
	// 				return nil, err
	// 			}
	// 			zone.dsRRs = append(zone.dsRRs, dsRRs...)

	// 			stack = stack.push(zone)
	// 		}

	// 		return append(stack.collect(), answer...), nil
	// 	}

	// // If r contains a DNAME, replace target suffix (which should equal the
	// // current zone) with the one referenced in the
	// // DNAME and replace current zone with the one referenced in the
	// // DNAME. Then pop RRs off the stack for each zone until the new target is
	// // within the current zone. Jump to the top of the loop for this subdomain


	// }

	// // query for:
	// // - root zone "."

	// // DNSKEY ksk # confirm that this matches hardcoded public key
	// // DNSKEY zsk
	// // RRSIG DNSKEY

	// // - next zone repeat until this domain == target domain
	// // DNSKEY ksk # confirm that this matches hardcoded public key
	// // DNSKEY zsk
	// // RRSIG DNSKEY

	// // DS
	// // RRSIG DS

	// // (if this domain == target domain)
	// // TXT
	// // RRSIG TXT
	// return append(stack.collect(), answer...), nil
}

// Check if the provided key is a key-signing key
func checkIfKSK(key *dns.DNSKEY) bool {
	// is zone key
	isKey := 0 != key.Flags & dns.ZONE

	// is Secure Entry Point
	isSEP := 0 != key.Flags & dns.SEP

	return isKey && isSEP
}

func convertDnskeyToKey(dnskey *dns.DNSKEY) dns.Key {
	k := dns.Key{
		Flags: dnskey.Flags,
		Protocol: dnskey.Protocol,
		Algorithm: dnskey.Algorithm,
		Public_key: []byte(dnskey.PublicKey),
	}
	k.Length = uint16(dns.Len(&k))
	return k
}

func convertDsToSerialDs(ds *dns.DS) dns.SerialDS {
	s := dns.SerialDS{
		Key_tag: ds.KeyTag,
		Algorithm: ds.Algorithm,
		Digest_type: ds.DigestType,
		Digest: []byte(ds.Digest),
	}
	s.Digest_len = uint16(len(s.Digest))
	s.Length = uint16(dns.Len(&s))
	return s
}

func convertRrsigToSignature(rrsig *dns.RRSIG) dns.Signature {
	s := dns.Signature{
		Algorithm: rrsig.Algorithm,
		Labels: rrsig.Labels,
		Ttl: rrsig.OrigTtl,
		Expires: rrsig.Expiration,
		Begins: rrsig.Inception,
		Key_tag: rrsig.KeyTag,
		Signature: []byte(rrsig.Signature),
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
		Keys: make([]dns.Key, 0),
	}
	currentExit := &dns.Leaving{
		ZType: dns.LeavingType,
		LeavingType: dns.LeavingUncommitted,
	}

	for _, v := range rrs {
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
				Exit: *currentExit,
			}
			zones = append(zones, zp)

			// create new entry and exit for the new current zone
			currentEntry = &dns.Entering{
				ZType: dns.EnteringType,
				Keys: make([]dns.Key, 0),
			}
			currentExit = &dns.Leaving{
				ZType: dns.LeavingType,
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
			}

		case *dns.CNAME:
			return dns.DNSSECProof{}, errors.New("CNAME is not supported")
		case *dns.DNAME:
			return dns.DNSSECProof{}, errors.New("DNAME is not supported")
		case *dns.TXT:
			addLeafRR(currentExit, v)
		case *dns.A:
			addLeafRR(currentExit, v)
		case *dns.AAAA:
			addLeafRR(currentExit, v)
		default:
			return dns.DNSSECProof{}, errors.New("Type " + t.String() + " is not supported")
		}
	}

	// populate the remaining fields from the previous zone
	currentEntry.Length = uint16(dns.Len(currentEntry))
	currentEntry.Num_keys = uint8(len(currentEntry.Keys))
	currentExit.Length = uint16(dns.Len(currentExit))

	// append previous zone's entries to struct
	zp := dns.ZonePair{
		Entry: *currentEntry,
		Exit: *currentExit,
	}
	zones = append(zones, zp)

	return dns.DNSSECProof{
		Hdr: dns.RR_Header{
			Rrtype: dns.TypeDNSSECProof,
		},
		// NOTE zero indicates that we're using the root zone's key-signing key
		Initial_key_tag: 0,
		Num_zones: uint8(len(zones)),
		Zones: zones,
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

func (s *targetServer) resolveQueryWithResolver(q *dns.Msg, r resolver) ([]byte, error) {

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
			return nil, err
		}

		response.Extra = append(response.Extra, &dnssecProof)
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

func (s *targetServer) dohQueryHandler(w http.ResponseWriter, r *http.Request) {
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

func (s *targetServer) parseObliviousQueryFromRequest(r *http.Request) (odoh.ObliviousDNSMessage, error) {
	if r.Method != http.MethodPost {
		return odoh.ObliviousDNSMessage{}, fmt.Errorf("Unsupported HTTP method for Oblivious DNS query: %s", r.Method)
	}

	defer r.Body.Close()
	encryptedMessageBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return odoh.ObliviousDNSMessage{}, err
	}

	return odoh.UnmarshalDNSMessage(encryptedMessageBytes)
}

func (s *targetServer) createObliviousResponseForQuery(context odoh.ResponseContext, dnsResponse []byte) (odoh.ObliviousDNSMessage, error) {
	response := odoh.CreateObliviousDNSResponse(dnsResponse, 0)
	odohResponse, err := context.EncryptResponse(response)

	if s.verbose {
		log.Printf("Encrypted response: %x", odohResponse)
	}

	return odohResponse, err
}

func (s *targetServer) odohQueryHandler(w http.ResponseWriter, r *http.Request) {
	requestReceivedTime := time.Now()
	exp := experiment{}
	exp.ExperimentID = s.experimentId
	exp.IngestedFrom = s.serverInstanceName
	exp.ProtocolType = "ODOH"
	timestamp := runningTime{}

	timestamp.Start = requestReceivedTime.UnixNano()
	odohMessage, err := s.parseObliviousQueryFromRequest(r)
	if err != nil {
		log.Println("parseObliviousQueryFromRequest failed:", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	obliviousQuery, responseContext, err := s.odohKeyPair.DecryptQuery(odohMessage)
	if err != nil {
		log.Println("DecryptQuery failed:", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	query, err := decodeDNSQuestion(obliviousQuery.Message())
	if err != nil {
		log.Println("decodeDNSQuestion failed:", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	queryParseAndDecryptionCompleteTime := time.Now().UnixNano()
	timestamp.TargetQueryDecryptionTime = queryParseAndDecryptionCompleteTime

	chosenResolver := rand.Intn(len(s.resolver))
	packedResponse, err := s.resolveQueryWithResolver(query, s.resolver[chosenResolver])
	if err != nil {
		log.Println("resolveQueryWithResolver failed:", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	queryResolutionCompleteTime := time.Now().UnixNano()
	timestamp.TargetQueryResolutionTime = queryResolutionCompleteTime

	obliviousResponse, err := s.createObliviousResponseForQuery(responseContext, packedResponse)
	if err != nil {
		log.Println("createObliviousResponseForQuery failed:", err)
		timestamp.TargetAnswerEncryptionTime = 0
		timestamp.EndTime = 0
		exp.Timestamp = timestamp
		exp.Status = false
		exp.Resolver = ""
		if s.telemetryClient.logClient != nil {
			go s.telemetryClient.streamTelemetryToGCPLogging([]string{exp.serialize()})
		} else if s.telemetryClient.esClient != nil {
			go s.telemetryClient.streamDataToElastic([]string{exp.serialize()})
		}
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	packedResponseMessage := obliviousResponse.Marshal()

	answerEncryptionAndSerializeCompletionTime := time.Now().UnixNano()
	timestamp.TargetAnswerEncryptionTime = answerEncryptionAndSerializeCompletionTime

	if s.verbose {
		log.Printf("Target response: %x", packedResponseMessage)
	}

	returnResponseTime := time.Now().UnixNano()
	timestamp.EndTime = returnResponseTime

	exp.Timestamp = timestamp
	exp.Resolver = s.resolver[chosenResolver].name()
	exp.Status = true

	if s.telemetryClient.logClient != nil {
		go s.telemetryClient.streamTelemetryToGCPLogging([]string{exp.serialize()})
	} else if s.telemetryClient.esClient != nil {
		go s.telemetryClient.streamDataToElastic([]string{exp.serialize()})
	}

	w.Header().Set("Content-Type", odohMessageContentType)
	w.Write(packedResponseMessage)
}

func (s *targetServer) targetQueryHandler(w http.ResponseWriter, r *http.Request) {
	if s.verbose {
		log.Printf("%s Handling %s\n", r.Method, r.URL.Path)
	}

	if r.Header.Get("Content-Type") == dnsMessageContentType {
		s.dohQueryHandler(w, r)
	} else if r.Header.Get("Content-Type") == odohMessageContentType {
		s.odohQueryHandler(w, r)
	} else {
		log.Printf("Invalid content type: %s", r.Header.Get("Content-Type"))
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
	}
}

func (s *targetServer) configHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s Handling %s\n", r.Method, r.URL.Path)

	configSet := []odoh.ObliviousDoHConfig{s.odohKeyPair.Config}
	configs := odoh.CreateObliviousDoHConfigs(configSet)
	w.Write(configs.Marshal())
}
