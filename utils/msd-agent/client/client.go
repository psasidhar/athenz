// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package client

import (
	"fmt"
	"net/http"
	"os"
	"regexp"

	"github.com/AthenZ/athenz/libs/go/athenz-common/log"
	"github.com/AthenZ/athenz/libs/go/tls/config"
	svc "github.com/AthenZ/athenz/utils/msd-agent/svc"

	"github.com/AthenZ/athenz/clients/go/msd"
)

const USER_AGENT = "User-Agent"

type MsdClient interface {
	PutWorkload(domain string, service string, options *msd.WorkloadOptions, resourceOwner string) error
}

type Client struct {
	Url              string
	Transport        *http.Transport
	AuthzHeaderName  string
	AuthzHeaderValue string
}

var version = ""

func (c Client) PutWorkload(domain string, service string, options *msd.WorkloadOptions, resourceOwner string) error {
	msdClient := clientWithUserAgent(c)
	return msdClient.PutDynamicWorkload(msd.DomainName(domain), msd.EntityName(service), options, resourceOwner)
}

func clientWithUserAgent(c Client) msd.MSDClient {
	msdClient := msd.NewClient(c.Url, c.Transport)
	osVersion := func() string {
		b, err := os.ReadFile("/etc/redhat-release")
		if err != nil {
			log.Debugf("Failed to read os version")
			return ""
		}
		versionReg, _ := regexp.Compile(`\d+\.\d+`)
		v := versionReg.FindString(string(b))
		return fmt.Sprintf("rhel-%s", v)
	}
	msdClient.AddCredentials(USER_AGENT, fmt.Sprintf("c:%s %s", version, osVersion()))
	if c.AuthzHeaderName != "" && c.AuthzHeaderValue != "" {
		msdClient.AddCredentials(c.AuthzHeaderName, c.AuthzHeaderValue)
	}
	return msdClient
}

func NewClient(msdAgentVersion string, url string, domain string, service string) (*Client, error) {
	return NewClientWithAuthz(msdAgentVersion, url, domain, service, "", "")
}

func NewClientWithAuthz(msdAgentVersion, url, domain, service, authzHeaderName, authzHeaderValue string) (*Client, error) {
	version = msdAgentVersion
	certFile := certFile(service, domain)
	keyFile := keyFile(service, domain)
	log.Printf("Creating MsdClient using cert: %s, and key: %s", certFile, keyFile)

	tlsConfig, err := config.GetTLSConfigFromFiles(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	transport := http.Transport{
		TLSClientConfig: tlsConfig,
	}
	client := &Client{
		Url:              url,
		Transport:        &transport,
		AuthzHeaderName:  authzHeaderName,
		AuthzHeaderValue: authzHeaderValue,
	}
	return client, err
}

func certFile(service string, domain string) string {
	return svc.SIA_DIR + "/certs/" + domain + "." + service + ".cert.pem"
}

func keyFile(service string, domain string) string {
	return svc.SIA_DIR + "/keys/" + domain + "." + service + ".key.pem"
}
