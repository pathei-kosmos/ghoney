package main

import (
	"crypto/sha256"
	"net"
	"net/http"
	"time"
)

const (
	defaultPublicAddr  = ":8080"
	defaultAdminAddr   = "127.0.0.1:9090"
	maxRequestBodySize = 4 * 1024
	maxBodySnippetSize = 256
	maxEventFieldSize  = 1024
	maxHeaderBytes     = 16 * 1024
	// Include the 4 KiB buffered read margin from net/http
	maxDetectionSourceSize = maxHeaderBytes + 4*1024
	// Leave room for Unicode case folding without losing the tail
	maxCanonicalSourceSize = maxDetectionSourceSize * 2
	maxDetectionSources    = 20
	maxDecodePasses        = 12
	maxNestedGzipLayers    = 8
	maxBase64DecodePasses  = 3
	maxGzipDecodedWorkSize = maxRequestBodySize * maxNestedGzipLayers
	maxXMLExpansionSize    = maxRequestBodySize * 8
	maxDataURIMetadataSize = 512
	requestTimeout         = 5 * time.Second
	shutdownTimeout        = 5 * time.Second
	logBufferSize          = 100
	logHighReserve         = 50
	logMediumReserve       = 30
	logWeakReserve         = 20
	maxConcurrentPublic    = 128
	maxConcurrentAdmin     = 32
	envPublicAddr          = "GHONEY_ADDR"
	envAdminAddr           = "GHONEY_ADMIN_ADDR"
	envAdminUser           = "GHONEY_ADMIN_USER"
	envAdminPassword       = "GHONEY_ADMIN_PASSWORD"
	envAdminPasswordFile   = "GHONEY_ADMIN_PASSWORD_FILE"
	defaultAdminUser       = "ghoney"
	minAdminPasswordBytes  = 16
	maxAdminPasswordBytes  = 256
	maxJNDIExpansionPasses = 6
	minBase64ValueSize     = 8
	unknownMetricRoute     = "not_found"
	unknownMetricMethod    = "OTHER"
)

// adminCredentials stores only fixed size credential hashes
type adminCredentials struct {
	enabled      bool
	usernameHash [sha256.Size]byte
	passwordHash [sha256.Size]byte
}

// appConfig holds validated settings for both listeners
type appConfig struct {
	publicAddr      string
	adminAddr       string
	adminCredential adminCredentials
}

// runtimeDependencies make listener startup easy to test
type runtimeDependencies struct {
	listen func(network, address string) (net.Listener, error)
	serve  func(server *http.Server, listener net.Listener) error
}
