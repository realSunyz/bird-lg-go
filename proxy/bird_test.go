package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"strings"
	"testing"

	"github.com/magiconair/properties/assert"
)

type BirdServer struct {
	t             *testing.T
	expectedQuery string
	response      string
	server        net.Listener
	socket        string
	injectError   string
}

func (s *BirdServer) initSocket() {
	tmpDir, err := ioutil.TempDir("", "bird-lgproxy-go-mock")
	if err != nil {
		s.t.Fatal(err)
	}
	s.socket = path.Join(tmpDir, "mock.socket")
}

func (s *BirdServer) Listen() {
	s.initSocket()

	var err error
	s.server, err = net.Listen("unix", s.socket)
	if err != nil {
		s.t.Error(err)
	}
}

func (s *BirdServer) Run() {
	for {
		conn, err := s.server.Accept()
		if err != nil {
			break
		}
		if conn == nil {
			break
		}

		reader := bufio.NewReader(conn)

		conn.Write([]byte("1234 Hello from mock bird\n"))

		query, err := reader.ReadBytes('\n')
		if err != nil {
			break
		}
		if strings.TrimSpace(string(query)) != "restrict" {
			s.t.Errorf("Did not restrict bird permissions")
		}
		if s.injectError == "restriction" {
			conn.Write([]byte("1234 Restriction is disabled!\n"))
		} else {
			conn.Write([]byte("1234 Access restricted\n"))
		}

		query, err = reader.ReadBytes('\n')
		if err != nil {
			break
		}
		if strings.TrimSpace(string(query)) != s.expectedQuery {
			s.t.Errorf("Query %s doesn't match expectation %s", string(query), s.expectedQuery)
		}

		responseList := strings.Split(s.response, "\n")
		for i := range responseList {
			if i == len(responseList)-1 {
				if s.injectError == "eof" {
					conn.Write([]byte("0000 " + responseList[i]))
				} else {
					conn.Write([]byte("0000 " + responseList[i] + "\n"))
				}
			} else {
				conn.Write([]byte("1234 " + responseList[i] + "\n"))
			}
		}

		conn.Close()
	}
}

func (s *BirdServer) Close() {
	if s.server == nil {
		return
	}
	s.server.Close()
}

func signPayload(t *testing.T, priv *ecdsa.PrivateKey, payload string) string {
	t.Helper()
	digest := sha256.Sum256([]byte(payload))
	sig, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(sig)
}

func TestBirdReadln(t *testing.T) {
	input := strings.NewReader("1234 Bird Message\n")
	var output bytes.Buffer
	birdReadln(input, &output)

	assert.Equal(t, output.String(), "Bird Message\n")
}

func TestBirdReadlnNoPrefix(t *testing.T) {
	input := strings.NewReader(" Message without prefix\n")
	var output bytes.Buffer
	birdReadln(input, &output)

	assert.Equal(t, output.String(), "Message without prefix\n")
}

func TestBirdReadlnVeryLongLine(t *testing.T) {
	input := strings.NewReader(strings.Repeat("A", 4096))
	var output bytes.Buffer
	birdReadln(input, &output)

	assert.Equal(t, output.String(), strings.Repeat("A", 1022)+"\n")
}

func TestBirdWriteln(t *testing.T) {
	var output bytes.Buffer
	birdWriteln(&output, "Test command")
	assert.Equal(t, output.String(), "Test command\n")
}

func TestBirdHandlerWithoutQuery(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/bird", nil)
	w := httptest.NewRecorder()
	birdHandler(w, r)
}

func TestBirdHandlerWithQuery(t *testing.T) {
	server := BirdServer{
		t:             t,
		expectedQuery: "show protocols",
		response:      "Mock Response\nSecond Line",
		injectError:   "",
	}

	server.Listen()
	go server.Run()
	defer server.Close()

	setting.birdSocket = server.socket

	r := httptest.NewRequest(http.MethodGet, "/bird?q="+url.QueryEscape(server.expectedQuery), nil)
	w := httptest.NewRecorder()
	birdHandler(w, r)

	assert.Equal(t, w.Code, http.StatusOK)
	assert.Equal(t, w.Body.String(), server.response+"\n")
}

func TestBirdHandlerWithBadSocket(t *testing.T) {
	setting.birdSocket = "/nonexistent.sock"

	r := httptest.NewRequest(http.MethodGet, "/bird?q="+url.QueryEscape("mock"), nil)
	w := httptest.NewRecorder()
	birdHandler(w, r)

	assert.Equal(t, w.Code, http.StatusInternalServerError)
}

func TestBirdHandlerWithoutRestriction(t *testing.T) {
	server := BirdServer{
		t:             t,
		expectedQuery: "show protocols",
		response:      "Mock Response",
		injectError:   "restriction",
	}

	server.Listen()
	go server.Run()
	defer server.Close()

	setting.birdSocket = server.socket

	r := httptest.NewRequest(http.MethodGet, "/bird?q="+url.QueryEscape("mock"), nil)
	w := httptest.NewRecorder()
	birdHandler(w, r)

	assert.Equal(t, w.Code, http.StatusInternalServerError)
}

func TestBirdHandlerEOF(t *testing.T) {
	server := BirdServer{
		t:             t,
		expectedQuery: "show protocols",
		response:      "Mock Response\nSecond Line",
		injectError:   "eof",
	}

	server.Listen()
	go server.Run()
	defer server.Close()

	setting.birdSocket = server.socket

	r := httptest.NewRequest(http.MethodGet, "/bird?q="+url.QueryEscape("show protocols"), nil)
	w := httptest.NewRecorder()
	birdHandler(w, r)

	assert.Equal(t, w.Code, http.StatusOK)
	assert.Equal(t, w.Body.String(), "Mock Response\nEOF")
}

func TestBirdHandlerSignatureMissing(t *testing.T) {
	server := BirdServer{
		t:             t,
		expectedQuery: "show protocols",
		response:      "Mock Response",
		injectError:   "",
	}

	server.Listen()
	go server.Run()
	defer server.Close()

	setting.birdSocket = server.socket

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	setting.ecdsaPublic = &priv.PublicKey
	defer func() { setting.ecdsaPublic = nil }()

	r := httptest.NewRequest(http.MethodGet, "/bird?q="+url.QueryEscape(server.expectedQuery), nil)
	w := httptest.NewRecorder()
	birdHandler(w, r)

	assert.Equal(t, w.Code, http.StatusUnauthorized)
}

func TestBirdHandlerSignatureValid(t *testing.T) {
	server := BirdServer{
		t:             t,
		expectedQuery: "show protocols",
		response:      "Mock Response",
		injectError:   "",
	}

	server.Listen()
	go server.Run()
	defer server.Close()

	setting.birdSocket = server.socket

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	setting.ecdsaPublic = &priv.PublicKey
	defer func() { setting.ecdsaPublic = nil }()

	sig := signPayload(t, priv, server.expectedQuery)
	r := httptest.NewRequest(http.MethodGet, "/bird?q="+url.QueryEscape(server.expectedQuery)+"&sig="+url.QueryEscape(sig), nil)
	w := httptest.NewRecorder()
	birdHandler(w, r)

	assert.Equal(t, w.Code, http.StatusOK)
	assert.Equal(t, w.Body.String(), server.response+"\n")
}
