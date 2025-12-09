package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/jarcoal/httpmock"
)

func TestBatchRequestIPv4(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpResponse := httpmock.NewStringResponder(200, "Mock Result")
	httpmock.RegisterResponder("GET", "http://1.1.1.1:8000/mock?q=cmd", httpResponse)
	httpmock.RegisterResponder("GET", "http://2.2.2.2:8000/mock?q=cmd", httpResponse)
	httpmock.RegisterResponder("GET", "http://3.3.3.3:8000/mock?q=cmd", httpResponse)

	setting.servers = []string{
		"1.1.1.1",
		"2.2.2.2",
		"3.3.3.3",
	}
	setting.domain = ""
	setting.proxyPort = 8000
	response := batchRequest(setting.servers, "mock", "cmd")

	if len(response) != 3 {
		t.Error("Did not get response of all three mock servers")
	}
	for i := 0; i < len(response); i++ {
		if response[i] != "Mock Result" {
			t.Error("HTTP response mismatch")
		}
	}
}

func TestBatchRequestIPv6(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpResponse := httpmock.NewStringResponder(200, "Mock Result")
	httpmock.RegisterResponder("GET", "http://[2001:db8::1]:8000/mock?q=cmd", httpResponse)
	httpmock.RegisterResponder("GET", "http://[2001:db8::2]:8000/mock?q=cmd", httpResponse)
	httpmock.RegisterResponder("GET", "http://[2001:db8::3]:8000/mock?q=cmd", httpResponse)

	setting.servers = []string{
		"2001:db8::1",
		"2001:db8::2",
		"2001:db8::3",
	}
	setting.domain = ""
	setting.proxyPort = 8000
	response := batchRequest(setting.servers, "mock", "cmd")

	if len(response) != 3 {
		t.Error("Did not get response of all three mock servers")
	}
	for i := 0; i < len(response); i++ {
		if response[i] != "Mock Result" {
			t.Error("HTTP response mismatch")
		}
	}
}

func TestBatchRequestEmptyResponse(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpResponse := httpmock.NewStringResponder(200, "")
	httpmock.RegisterResponder("GET", "http://alpha:8000/mock?q=cmd", httpResponse)
	httpmock.RegisterResponder("GET", "http://beta:8000/mock?q=cmd", httpResponse)
	httpmock.RegisterResponder("GET", "http://gamma:8000/mock?q=cmd", httpResponse)

	setting.servers = []string{
		"alpha",
		"beta",
		"gamma",
	}
	setting.domain = ""
	setting.proxyPort = 8000
	response := batchRequest(setting.servers, "mock", "cmd")

	if len(response) != 3 {
		t.Error("Did not get response of all three mock servers")
	}
	for i := 0; i < len(response); i++ {
		if !strings.Contains(response[i], "node returned empty response") {
			t.Error("Did not produce error for empty response")
		}
	}
}

func TestBatchRequestDomainSuffix(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpResponse := httpmock.NewStringResponder(200, "Mock Result")
	httpmock.RegisterResponder("GET", "http://alpha.suffix:8000/mock?q=cmd", httpResponse)
	httpmock.RegisterResponder("GET", "http://beta.suffix:8000/mock?q=cmd", httpResponse)
	httpmock.RegisterResponder("GET", "http://gamma.suffix:8000/mock?q=cmd", httpResponse)

	setting.servers = []string{
		"alpha",
		"beta",
		"gamma",
	}
	setting.domain = "suffix"
	setting.proxyPort = 8000
	response := batchRequest(setting.servers, "mock", "cmd")

	if len(response) != 3 {
		t.Error("Did not get response of all three mock servers")
	}
	for i := 0; i < len(response); i++ {
		if response[i] != "Mock Result" {
			t.Error("HTTP response mismatch")
		}
	}
}

func TestBatchRequestHTTPError(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpError := httpmock.NewErrorResponder(errors.New("Oops!"))
	httpmock.RegisterResponder("GET", "http://alpha:8000/mock?q=cmd", httpError)
	httpmock.RegisterResponder("GET", "http://beta:8000/mock?q=cmd", httpError)
	httpmock.RegisterResponder("GET", "http://gamma:8000/mock?q=cmd", httpError)

	setting.servers = []string{
		"alpha",
		"beta",
		"gamma",
	}
	setting.domain = ""
	setting.proxyPort = 8000
	response := batchRequest(setting.servers, "mock", "cmd")

	if len(response) != 3 {
		t.Error("Did not get response of all three mock servers")
	}
	for i := 0; i < len(response); i++ {
		if !strings.Contains(response[i], "request failed") {
			t.Error("Did not produce HTTP error")
		}
	}
}

func TestBatchRequestInvalidServer(t *testing.T) {
	setting.servers = []string{}
	setting.domain = ""
	setting.proxyPort = 8000
	response := batchRequest([]string{"invalid"}, "mock", "cmd")

	if len(response) != 1 {
		t.Error("Did not get response of all mock servers")
	}
	if !strings.Contains(response[0], "invalid server") {
		t.Error("Did not produce invalid server error")
	}
}

func TestBatchRequestWithSignature(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	setting.ecdsaPrivate = priv
	defer func() { setting.ecdsaPrivate = nil }()

	httpmock.RegisterResponder("GET", "=~^http://1\\.1\\.1\\.1:8000/mock\\?q=cmd(&sig=.*)?$",
		func(req *http.Request) (*http.Response, error) {
			sig := req.URL.Query().Get("sig")
			if sig == "" {
				t.Error("missing signature")
			} else {
				decoded, err := base64.StdEncoding.DecodeString(sig)
				if err != nil {
					t.Error(err)
				}
				digest := sha256.Sum256([]byte("cmd"))
				if !ecdsa.VerifyASN1(&priv.PublicKey, digest[:], decoded) {
					t.Error("signature verification failed")
				}
			}
			return httpmock.NewStringResponse(200, "Mock Result"), nil
		},
	)

	setting.servers = []string{
		"1.1.1.1",
	}
	setting.domain = ""
	setting.proxyPort = 8000
	response := batchRequest(setting.servers, "mock", "cmd")

	if len(response) != 1 {
		t.Error("Did not get response of all mock servers")
	}
	if response[0] != "Mock Result" {
		t.Error("HTTP response mismatch")
	}
}
