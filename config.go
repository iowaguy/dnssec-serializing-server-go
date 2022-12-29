package main

import (
	"encoding/hex"
	"gopkg.in/yaml.v3"
	"log"
	"net"
	"os"
)

type Configuration struct {
	SupportedProtocols []string `yaml:"protocols"`
	HTTPS              struct {
		Port     string `yaml:"port"`
		Endpoint string `yaml:"endpoint"`
	} `yaml:"https"`
	UDP struct {
		Host string `yaml:"host"`
		Port string `yaml:"port"`
		Size int    `yaml:"size"`
	} `yaml:"udp"`
	TCP struct {
		Host string `yaml:"host"`
		Port string `yaml:"port"`
	} `yaml:"tcp"`
	ODoH struct {
		Seed           string `yaml:"seed"`
		ConfigEndpoint string `yaml:"config_endpoint"`
	} `yaml:"odoh"`
	UpstreamNameservers []string `yaml:"upstream"`

	// private
	protocolMap map[string]bool
}

func (c *Configuration) getUDPBindAddr() string {
	return net.JoinHostPort(c.UDP.Host, c.UDP.Port)
}

func (c *Configuration) getUDPResponsePacketSize() int {
	return c.UDP.Size
}

func (c *Configuration) getTCPBindAddr() string {
	return net.JoinHostPort(c.TCP.Host, c.TCP.Port)
}

func (c *Configuration) getDoHPort() string {
	return c.HTTPS.Port
}

func (c *Configuration) getDoHEndpoint() string {
	return c.HTTPS.Endpoint
}

func (c *Configuration) getODoHConfigEndpoint() string {
	return c.ODoH.ConfigEndpoint
}

func (c *Configuration) getODoHKeyPairGenSeed() []byte {
	seed, err := hex.DecodeString(c.ODoH.Seed)
	if err != nil {
		log.Fatalf("unable to decode the seed correctly. Please pass correct configuration")
	}
	return seed
}

func (c *Configuration) getConfiguredUpstreamResolvers() []string {
	return c.UpstreamNameservers
}

func (c *Configuration) supportedProtocol(protocol string) bool {
	if r, ok := c.protocolMap[protocol]; ok {
		return r
	}
	return false
}

func LoadConfig(configPath string) Configuration {
	c := Configuration{}
	data, err := os.ReadFile(configPath)
	if err != nil {
		log.Fatalf("unable to read configuration at the provided path: %v\nError: %v\n", configPath, err)
	}
	err = yaml.Unmarshal(data, &c)
	if err != nil {
		log.Fatalln("failed to unmarshal yaml, unable to read key information")
	}
	m := make(map[string]bool)
	for _, protocol := range c.SupportedProtocols {
		m[protocol] = true
	}
	c.protocolMap = m
	return c
}
