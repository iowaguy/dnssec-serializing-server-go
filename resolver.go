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
	"github.com/allegro/bigcache/v3"
	"net"
	"time"

	"github.com/miekg/dns"
)

type resolver interface {
	name() string
	resolve(query *dns.Msg) (*dns.Msg, error)
}

type targetResolver struct {
	nameserver string
	timeout    time.Duration
	cache      *bigcache.BigCache
}

func (s targetResolver) name() string {
	return s.nameserver
}

func (s targetResolver) resolve(query *dns.Msg) (*dns.Msg, error) {
	var err error
	// Lookup cache first
	queryFQDN := query.Question[0].Name
	queryQType := query.Question[0].Qtype
	cacheKey := fmt.Sprintf("%v|%v", queryFQDN, queryQType)
	// Greedy optimization for only caching Root, TLD and ignore others
	potentialInCache := len(dns.SplitDomainName(queryFQDN)) < 2
	if potentialInCache {
		entry, err := s.cache.Get(cacheKey)
		if err != nil {
			goto performNetworking
		}
		resp := new(dns.Msg)
		if err := resp.Unpack(entry); err != nil {
			goto performNetworking
		}
		resp.Id = query.Id
		return resp, err
	}

performNetworking:
	{
	}
	connection := new(dns.Conn)

	if connection.Conn, err = net.DialTimeout("tcp", s.nameserver, s.timeout*time.Millisecond); err != nil {
		return nil, fmt.Errorf("failed starting resolver connection")
	}

	err = connection.SetReadDeadline(time.Now().Add(s.timeout * time.Millisecond))
	if err != nil {
		return nil, err
	}
	err = connection.SetWriteDeadline(time.Now().Add(s.timeout * time.Millisecond))
	if err != nil {
		return nil, err
	}

	if err := connection.WriteMsg(query); err != nil {
		return nil, err
	}

	response, err := connection.ReadMsg()
	if err != nil {
		return nil, err
	}

	if potentialInCache {
		respBuffer, err := response.Pack()
		if err != nil {
			fmt.Println("Unable to pack the response correctly. Malformed?")
		}
		err = s.cache.Set(cacheKey, respBuffer)
		if err != nil {
			fmt.Println("Unable to insert data into cache.")
		}
	}

	response.Id = query.Id
	return response, nil
}
