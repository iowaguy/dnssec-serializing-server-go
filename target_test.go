// The MIT License
//
// Copyright (c) 2020, Cloudflare, Inc. All rights reserved.
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
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	odoh "github.com/cloudflare/odoh-go"
	"github.com/miekg/dns"
)

type localResolver struct {
	queries          []string
	queryResponseMap map[string][]byte // Packed DNS queries to responses
}

func (r localResolver) name() string {
	return "localResolver"
}

func (r localResolver) resolve(query *dns.Msg) (*dns.Msg, error) {
	packedQuery, err := query.Pack()
	if err != nil {
		return nil, err
	}

	// Ignore the first two bytes which are the query ID. The query ID changes every time.
	packedQuery[0] = 0
	packedQuery[1] = 0
	packed, ok := r.queryResponseMap[string(packedQuery)]
	if !ok {
		return nil, errors.New("Failed to resolve")
	}

	response := &dns.Msg{}
	err = response.Unpack(packed)

	return response, err
}

func createTestDS(t *testing.T, domain string) ([]byte, []byte, []dns.RR) {
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(domain), dns.TypeDS)
	q.SetEdns0(4096, true)
	packedQuery, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}

	r := new(dns.Msg)
	r.SetReply(q)
	dnskeyAnswers := make([]dns.RR, 2)
	dnskeyAnswers[0] = &dns.DS{
		Hdr: dns.RR_Header{
			Name:   q.Question[0].Name,
			Rrtype: dns.TypeDS,
			Class:  dns.ClassINET,
			Ttl:    0,
		},
		KeyTag:     35886,
		Algorithm:  8,
		DigestType: 2,
		Digest:     "abcd",
	}
	dnskeyAnswers[1] = &dns.RRSIG{
		Hdr: dns.RR_Header{
			Name:   q.Question[0].Name,
			Rrtype: dns.TypeRRSIG,
			Class:  dns.ClassINET,
			Ttl:    0,
		},
		TypeCovered: dns.TypeDS,
		Algorithm:   0,
		Labels:      0,
		OrigTtl:     0,
		Expiration:  0,
		Inception:   0,
		KeyTag:      0,
		SignerName:  dns.Fqdn(domain),
		Signature:   "abcd",
	}

	r.Answer = dnskeyAnswers
	packedResponse, err := r.Pack()
	if err != nil {
		t.Fatal(err)
	}

	// Ignore the first two bytes which are the query ID. The query ID changes every time.
	packedQuery[0] = 0
	packedQuery[1] = 0
	return packedQuery, packedResponse, r.Answer
}

func createTestDNSKEYs(t *testing.T, domain string) ([]byte, []byte, []dns.RR) {
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(domain), dns.TypeDNSKEY)
	q.SetEdns0(4096, true)
	packedQuery, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}

	r := new(dns.Msg)
	r.SetReply(q)
	dnskeyAnswers := make([]dns.RR, 0)

	if domain == "a.foo.bar.com." {
		answerCNAME := &dns.CNAME{
			Hdr: dns.RR_Header{
				Name:   q.Question[0].Name,
				Rrtype: dns.TypeCNAME,
				Class:  dns.ClassINET,
				Ttl:    0,
			},
			Target: dns.Fqdn("app.example.com."),
		}
		dnskeyAnswers = append(dnskeyAnswers, answerCNAME)
		answerRRSIG := &dns.RRSIG{
			Hdr: dns.RR_Header{
				Name:   q.Question[0].Name,
				Rrtype: dns.TypeRRSIG,
				Class:  dns.ClassINET,
				Ttl:    0,
			},
			TypeCovered: dns.TypeCNAME,
			Algorithm:   0,
			Labels:      0,
			OrigTtl:     0,
			Expiration:  0,
			Inception:   0,
			KeyTag:      0,
			SignerName:  dns.Fqdn(domain),
			Signature:   "abcd",
		}
		dnskeyAnswers = append(dnskeyAnswers, answerRRSIG)
	}

	answerDNSKEY := &dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name:   q.Question[0].Name,
			Rrtype: dns.TypeDNSKEY,
			Class:  dns.ClassINET,
			Ttl:    0,
		},
		Flags:     257,
		Protocol:  3,
		Algorithm: 8,
		PublicKey: "abcd",
	}
	dnskeyAnswers = append(dnskeyAnswers, answerDNSKEY)

	answerDNSKEY = &dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name:   q.Question[0].Name,
			Rrtype: dns.TypeDNSKEY,
			Class:  dns.ClassINET,
			Ttl:    0,
		},
		Flags:     256,
		Protocol:  3,
		Algorithm: 8,
		PublicKey: "abcd",
	}
	dnskeyAnswers = append(dnskeyAnswers, answerDNSKEY)

	answerRRSIG := &dns.RRSIG{
		Hdr: dns.RR_Header{
			Name:   q.Question[0].Name,
			Rrtype: dns.TypeRRSIG,
			Class:  dns.ClassINET,
			Ttl:    0,
		},
		TypeCovered: dns.TypeDNSKEY,
		Algorithm:   0,
		Labels:      0,
		OrigTtl:     0,
		Expiration:  0,
		Inception:   0,
		KeyTag:      0,
		SignerName:  dns.Fqdn(domain),
		Signature:   "abcd",
	}
	dnskeyAnswers = append(dnskeyAnswers, answerRRSIG)

	r.Answer = dnskeyAnswers
	packedResponse, err := r.Pack()
	if err != nil {
		t.Fatal(err)
	}

	// Ignore the first two bytes which are the query ID. The query ID changes every time.
	packedQuery[0] = 0
	packedQuery[1] = 0
	return packedQuery, packedResponse, r.Answer
}

func createTestARecord(t *testing.T) ([]byte, []byte) {
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	packedQuery, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}

	r := new(dns.Msg)
	r.SetReply(q)
	r.Answer = make([]dns.RR, 1)
	r.Answer[0] = &dns.A{
		Hdr: dns.RR_Header{
			Name:   q.Question[0].Name,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    0,
		},
		A: net.ParseIP("127.0.0.1"),
	}
	packedResponse, err := r.Pack()
	if err != nil {
		t.Fatal(err)
	}

	// Ignore the first two bytes which are the query ID. The query ID changes every time.
	packedQuery[0] = 0
	packedQuery[1] = 0
	return packedQuery, packedResponse
}

func createTestARecordDNSSEC(t *testing.T, domain string) ([]byte, []byte, []dns.RR) {
	domain = dns.Fqdn(domain)
	q := new(dns.Msg)
	q.SetQuestion(domain, dns.TypeA)
	q.SetEdns0(4096, true)
	packedQuery, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}

	r := new(dns.Msg)
	r.SetReply(q)
	r.Answer = make([]dns.RR, 0)
	answerA := &dns.A{
		Hdr: dns.RR_Header{
			Name:   q.Question[0].Name,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    0,
		},
		A: net.ParseIP("1.2.3.4"),
	}
	r.Answer = append(r.Answer, answerA)

	answerRRSIG := &dns.RRSIG{
		Hdr: dns.RR_Header{
			Name:   q.Question[0].Name,
			Rrtype: dns.TypeRRSIG,
			Class:  dns.ClassINET,
			Ttl:    0,
		},
		TypeCovered: dns.TypeA,
		Algorithm:   0,
		Labels:      0,
		OrigTtl:     0,
		Expiration:  0,
		Inception:   0,
		KeyTag:      0,
		SignerName:  dns.Fqdn(domain),
		Signature:   "abcd",
	}
	r.Answer = append(r.Answer, answerRRSIG)

	packedResponse, err := r.Pack()
	if err != nil {
		t.Fatal(err)
	}

	// Ignore the first two bytes which are the query ID. The query ID changes every time.
	packedQuery[0] = 0
	packedQuery[1] = 0
	return packedQuery, packedResponse, r.Answer
}

func createLocalDNSSECResolver(t *testing.T) (*localResolver, []dns.RR, []dns.RR) {
	queries := make([]string, 0)
	resultMap := make(map[string][]byte)
	allRRs := make([]dns.RR, 0)
	var answer []dns.RR

	domains := []string{
		".",
		"com.",
		"bar.com.",
		"foo.bar.com.",
		"a.foo.bar.com.",
		"example.com.",
		"app.example.com.",
	}

	for _, d := range domains {
		packedQuery, packedResponse, rrs := createTestDNSKEYs(t, d)
		queries = append(queries, string(packedQuery))
		resultMap[string(packedQuery)] = packedResponse
		allRRs = append(allRRs, rrs...)

		if d != "." {
			packedQuery, packedResponse, rrs := createTestDS(t, d)
			queries = append(queries, string(packedQuery))
			resultMap[string(packedQuery)] = packedResponse
			allRRs = append(allRRs, rrs...)
		}

		if d == "app.example.com." {
			packedQuery, packedResponse, answer = createTestARecordDNSSEC(t, d)
			queries = append(queries, string(packedQuery))
			resultMap[string(packedQuery)] = packedResponse
		}
	}

	return &localResolver{
		queries:          queries,
		queryResponseMap: resultMap,
	}, allRRs, answer
}

func createLocalResolver(t *testing.T) *localResolver {
	packedQuery, packedResponse, _ := createTestARecordDNSSEC(t, "example.com")

	queries := make([]string, 0)
	queries = append(queries, string(packedQuery))

	resultMap := make(map[string][]byte)
	resultMap[string(packedQuery)] = packedResponse

	return &localResolver{
		queries:          queries,
		queryResponseMap: resultMap,
	}
}

func createKeyPair(t *testing.T) odoh.ObliviousDoHKeyPair {
	seed := make([]byte, defaultSeedLength)
	rand.Read(seed)

	keyPair, err := odoh.CreateKeyPairFromSeed(kemID, kdfID, aeadID, seed)
	if err != nil {
		t.Fatal("Failed to create a private key. Exiting now.")
	}

	return keyPair
}

func createTarget(t *testing.T, r resolver) targetServer {
	return targetServer{
		resolver:        []resolver{r},
		odohKeyPair:     createKeyPair(t),
		telemetryClient: getTelemetryInstance("LOG"),
	}
}

func TestConfigHandler(t *testing.T) {
	r := createLocalResolver(t)
	target := createTarget(t, r)

	configSet := []odoh.ObliviousDoHConfig{target.odohKeyPair.Config}
	configs := odoh.CreateObliviousDoHConfigs(configSet)
	marshalledConfig := configs.Marshal()

	handler := http.HandlerFunc(target.configHandler)

	request, err := http.NewRequest("GET", configEndpoint, nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, request)

	if status := rr.Code; status != http.StatusOK {
		t.Fatal(fmt.Errorf("Failed request with error code: %d", status))
	}

	body, err := ioutil.ReadAll(rr.Result().Body)
	if err != nil {
		t.Fatal("Failed to read body:", err)
	}

	if !bytes.Equal(body, marshalledConfig) {
		t.Fatal("Received invalid config")
	}
}
func TestQueryHandlerInvalidContentType(t *testing.T) {
	r := createLocalResolver(t)
	target := createTarget(t, r)

	handler := http.HandlerFunc(target.targetQueryHandler)

	request, err := http.NewRequest("GET", queryEndpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Add("Content-Type", "application/not-the-droids-youre-looking-for")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, request)

	if status := rr.Result().StatusCode; status != http.StatusBadRequest {
		t.Fatal(fmt.Errorf("Result did not yield %d, got %d instead", http.StatusBadRequest, status))
	}
}

func TestQueryHandlerDoHWithPOST(t *testing.T) {
	r := createLocalResolver(t)
	target := createTarget(t, r)

	handler := http.HandlerFunc(target.targetQueryHandler)

	q := r.queries[0]
	request, err := http.NewRequest(http.MethodPost, queryEndpoint, bytes.NewReader([]byte(q)))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Add("Content-Type", dnsMessageContentType)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, request)

	if status := rr.Result().StatusCode; status != http.StatusOK {
		t.Fatal(fmt.Errorf("Result did not yield %d, got %d instead", http.StatusOK, status))
	}
	if rr.Result().Header.Get("Content-Type") != dnsMessageContentType {
		t.Fatal("Invalid content type response")
	}

	responseBody, err := ioutil.ReadAll(rr.Result().Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(responseBody, r.queryResponseMap[q]) {
		t.Fatal("Incorrect response received")
	}
}

//func TestQueryHandlerDoHWithGET(t *testing.T) {
//	r := createLocalResolver(t)
//	target := createTarget(t, r)
//
//	handler := http.HandlerFunc(target.targetQueryHandler)
//
//	q := r.queries[0]
//	encodedQuery := base64.RawURLEncoding.EncodeToString([]byte(q))
//
//	request, err := http.NewRequest(http.MethodGet, queryEndpoint+"?dns="+encodedQuery, nil)
//	if err != nil {
//		t.Fatal(err)
//	}
//	request.Header.Add("Content-Type", dnsMessageContentType)
//
//	rr := httptest.NewRecorder()
//	handler.ServeHTTP(rr, request)
//
//	if status := rr.Result().StatusCode; status != http.StatusOK {
//		t.Fatal(fmt.Errorf("Result did not yield %d, got %d instead", http.StatusOK, status))
//	}
//	if rr.Result().Header.Get("Content-Type") != dnsMessageContentType {
//		t.Fatal("Invalid content type response")
//	}
//
//	responseBody, err := ioutil.ReadAll(rr.Result().Body)
//	if err != nil {
//		t.Fatal(err)
//	}
//	if !bytes.Equal(responseBody, r.queryResponseMap[q]) {
//		t.Fatal("Incorrect response received")
//	}
//}

func rrSlicesEqual(a, b []dns.RR) (bool, error) {
	if len(a) != len(b) {
		return false, errors.New("slices have different lengths")
	}
	for i, v := range a {
		if v.String() != b[i].String() {
			return false, fmt.Errorf("slices have different values at index: %d", i)
		}
	}
	return true, nil
}

func TestRRFetchDNSSEC(t *testing.T) {
	r, allRRs, answer := createLocalDNSSECResolver(t)
	target := createTarget(t, r)
	rrs, err := target.fetchDnssecRecords("a.foo.bar.com", answer, r)
	if err != nil {
		t.Fatal(err)
	}

	if equal, err := rrSlicesEqual(rrs, append(allRRs, answer...)); !equal {
		t.Fatal("Incorrect DNSSEC records:", err)
	}
}

func TestQueryHandlerDoHWithInvalidMethod(t *testing.T) {
	r := createLocalResolver(t)
	target := createTarget(t, r)

	handler := http.HandlerFunc(target.targetQueryHandler)

	q := r.queries[0]
	encodedQuery := base64.RawURLEncoding.EncodeToString([]byte(q))
	request, err := http.NewRequest(http.MethodPut, queryEndpoint+"?dns="+encodedQuery, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Add("Content-Type", dnsMessageContentType)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, request)

	if status := rr.Result().StatusCode; status != http.StatusBadRequest {
		t.Fatal(fmt.Errorf("Result did not yield %d, got %d instead", http.StatusBadRequest, status))
	}
}

func TestQueryHandlerODoHWithInvalidMethod(t *testing.T) {
	r := createLocalResolver(t)
	target := createTarget(t, r)

	handler := http.HandlerFunc(target.targetQueryHandler)

	q := r.queries[0]
	obliviousQuery := odoh.CreateObliviousDNSQuery([]byte(q), 0)
	encryptedQuery, _, err := target.odohKeyPair.Config.Contents.EncryptQuery(obliviousQuery)
	if err != nil {
		t.Fatal(err)
	}

	request, err := http.NewRequest(http.MethodGet, queryEndpoint, bytes.NewReader(encryptedQuery.Marshal()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Add("Content-Type", odohMessageContentType)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, request)

	if status := rr.Result().StatusCode; status != http.StatusBadRequest {
		t.Fatal(fmt.Errorf("Result did not yield %d, got %d instead", http.StatusBadRequest, status))
	}
}

//func TestQueryHandlerODoH(t *testing.T) {
//	r := createLocalResolver(t)
//	target := createTarget(t, r)
//
//	handler := http.HandlerFunc(target.targetQueryHandler)
//
//	q := r.queries[0]
//	obliviousQuery := odoh.CreateObliviousDNSQuery([]byte(q), 0)
//	encryptedQuery, context, err := target.odohKeyPair.Config.Contents.EncryptQuery(obliviousQuery)
//	if err != nil {
//		t.Fatal(err)
//	}
//
//	request, err := http.NewRequest(http.MethodPost, queryEndpoint, bytes.NewReader(encryptedQuery.Marshal()))
//	if err != nil {
//		t.Fatal(err)
//	}
//	request.Header.Add("Content-Type", odohMessageContentType)
//
//	rr := httptest.NewRecorder()
//	handler.ServeHTTP(rr, request)
//
//	if status := rr.Result().StatusCode; status != http.StatusOK {
//		t.Fatal(fmt.Errorf("Result did not yield %d, got %d instead", http.StatusOK, status))
//	}
//	if rr.Result().Header.Get("Content-Type") != odohMessageContentType {
//		t.Fatal("Invalid content type response")
//	}
//
//	responseBody, err := ioutil.ReadAll(rr.Result().Body)
//	if err != nil {
//		t.Fatal(err)
//	}
//
//	odohQueryResponse, err := odoh.UnmarshalDNSMessage(responseBody)
//	if err != nil {
//		t.Fatal(err)
//	}
//
//	response, err := context.OpenAnswer(odohQueryResponse)
//	if err != nil {
//		t.Fatal(err)
//	}
//
//	if !bytes.Equal(response, r.queryResponseMap[q]) {
//		t.Fatal(fmt.Errorf("Incorrect response received. Got %v, expected %v", response, r.queryResponseMap[q]))
//	}
//}

func TestQueryHandlerODoHWithInvalidKey(t *testing.T) {
	r := createLocalResolver(t)
	target := createTarget(t, r)

	handler := http.HandlerFunc(target.targetQueryHandler)

	differentKeyPair := createKeyPair(t)
	q := r.queries[0]
	obliviousQuery := odoh.CreateObliviousDNSQuery([]byte(q), 0)
	encryptedQuery, _, err := differentKeyPair.Config.Contents.EncryptQuery(obliviousQuery)
	if err != nil {
		t.Fatal(err)
	}

	request, err := http.NewRequest(http.MethodPost, queryEndpoint, bytes.NewReader(encryptedQuery.Marshal()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Add("Content-Type", odohMessageContentType)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, request)

	if status := rr.Result().StatusCode; status != http.StatusBadRequest {
		t.Fatal(fmt.Errorf("Result did not yield %d, got %d instead", http.StatusBadRequest, status))
	}
}

func TestQueryHandlerODoHWithCorruptCiphertext(t *testing.T) {
	r := createLocalResolver(t)
	target := createTarget(t, r)

	handler := http.HandlerFunc(target.targetQueryHandler)

	q := r.queries[0]
	obliviousQuery := odoh.CreateObliviousDNSQuery([]byte(q), 0)
	encryptedQuery, _, err := target.odohKeyPair.Config.Contents.EncryptQuery(obliviousQuery)
	if err != nil {
		t.Fatal(err)
	}
	queryBytes := encryptedQuery.Marshal()
	queryBytes[len(queryBytes)-1] ^= 0xFF

	request, err := http.NewRequest(http.MethodPost, queryEndpoint, bytes.NewReader(queryBytes))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Add("Content-Type", odohMessageContentType)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, request)

	if status := rr.Result().StatusCode; status != http.StatusBadRequest {
		t.Fatal(fmt.Errorf("Result did not yield %d, got %d instead", http.StatusBadRequest, status))
	}
}
