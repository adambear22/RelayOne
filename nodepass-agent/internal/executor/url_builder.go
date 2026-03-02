package executor

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
)

func BuildServerURL(listenAddr, targetAddr, password string, tls, logLevel int) string {
	return fmt.Sprintf(
		"nodepass://server:%s@%s/%s?tls=%d&log=%d",
		url.QueryEscape(password),
		listenAddr,
		targetAddr,
		tls,
		logLevel,
	)
}

func BuildClientURL(serverAddr, targetAddr, password string, tls, logLevel int) string {
	return fmt.Sprintf(
		"nodepass://client:%s@%s/%s?tls=%d&log=%d",
		url.QueryEscape(password),
		serverAddr,
		targetAddr,
		tls,
		logLevel,
	)
}

func GeneratePassword() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "nodepass-default-password"
	}
	return hex.EncodeToString(buf)
}
