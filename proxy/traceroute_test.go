package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/magiconair/properties/assert"
)

func signTraceroutePayload(t *testing.T, priv *ecdsa.PrivateKey, payload string) string {
	t.Helper()
	digest := sha256.Sum256([]byte(payload))
	sig, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(sig)
}

func TestTracerouteArgsToString(t *testing.T) {
	result := tracerouteArgsToString("traceroute", []string{
		"-a",
		"-b",
		"-c",
	}, []string{
		"google.com",
	})

	assert.Equal(t, result, "traceroute -a -b -c google.com")
}

func TestTracerouteTryExecuteSuccess(t *testing.T) {
	_, err := tracerouteTryExecute("sh", []string{
		"-c",
	}, []string{
		"true",
	})

	if err != nil {
		t.Error(err)
	}
}

func TestTracerouteTryExecuteFail(t *testing.T) {
	_, err := tracerouteTryExecute("sh", []string{
		"-c",
	}, []string{
		"false",
	})

	if err == nil {
		t.Error("Should trigger error, not triggered")
	}
}

func TestTracerouteDetectSuccess(t *testing.T) {
	result := tracerouteDetect("sh", []string{
		"-c",
		"true",
	})

	assert.Equal(t, result, true)
}

func TestTracerouteDetectFail(t *testing.T) {
	result := tracerouteDetect("sh", []string{
		"-c",
		"false",
	})

	assert.Equal(t, result, false)
}

func TestTracerouteAutodetect(t *testing.T) {
	pathBackup := os.Getenv("PATH")
	os.Setenv("PATH", "")
	defer os.Setenv("PATH", pathBackup)

	setting.tr_bin = ""
	setting.tr_flags = []string{}
	tracerouteAutodetect()
	// Should not panic
}

func TestTracerouteAutodetectExisting(t *testing.T) {
	setting.tr_bin = "mock"
	setting.tr_flags = []string{"mock"}
	tracerouteAutodetect()
	assert.Equal(t, setting.tr_bin, "mock")
	assert.Equal(t, setting.tr_flags, []string{"mock"})
}

func TestTracerouteAutodetectFlagsOnly(t *testing.T) {
	pathBackup := os.Getenv("PATH")
	os.Setenv("PATH", "")
	defer os.Setenv("PATH", pathBackup)

	setting.tr_bin = "mock"
	setting.tr_flags = nil
	tracerouteAutodetect()

	// Should not panic
}

func TestTracerouteHandlerWithoutQuery(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/traceroute", nil)
	w := httptest.NewRecorder()
	tracerouteHandler(w, r)
	assert.Equal(t, w.Code, http.StatusInternalServerError)
	if !strings.Contains(w.Body.String(), "Invalid Request") {
		t.Error("Did not get invalid request")
	}
}

func TestTracerouteHandlerShlexError(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/traceroute?q="+url.QueryEscape("\"1.1.1.1"), nil)
	w := httptest.NewRecorder()
	tracerouteHandler(w, r)
	assert.Equal(t, w.Code, http.StatusInternalServerError)
	if !strings.Contains(w.Body.String(), "parse") {
		t.Error("Did not get parsing error message")
	}
}

func TestTracerouteHandlerNoTracerouteFound(t *testing.T) {
	setting.tr_bin = ""
	setting.tr_flags = nil

	r := httptest.NewRequest(http.MethodGet, "/traceroute?q="+url.QueryEscape("1.1.1.1"), nil)
	w := httptest.NewRecorder()
	tracerouteHandler(w, r)
	assert.Equal(t, w.Code, http.StatusInternalServerError)
	if !strings.Contains(w.Body.String(), "not supported") {
		t.Error("Did not get not supported error message")
	}
}

func TestTracerouteHandlerExecuteError(t *testing.T) {
	setting.tr_bin = "sh"
	setting.tr_flags = []string{"-c", "false"}
	setting.tr_raw = true

	r := httptest.NewRequest(http.MethodGet, "/traceroute?q="+url.QueryEscape("1.1.1.1"), nil)
	w := httptest.NewRecorder()
	tracerouteHandler(w, r)
	assert.Equal(t, w.Code, http.StatusInternalServerError)
	if !strings.Contains(w.Body.String(), "Error executing traceroute") {
		t.Error("Did not get not execute error message")
	}
}

func TestTracerouteHandlerRaw(t *testing.T) {
	setting.tr_bin = "sh"
	setting.tr_flags = []string{"-c", "echo Mock"}
	setting.tr_raw = true

	r := httptest.NewRequest(http.MethodGet, "/traceroute?q="+url.QueryEscape("1.1.1.1"), nil)
	w := httptest.NewRecorder()
	tracerouteHandler(w, r)
	assert.Equal(t, w.Code, http.StatusOK)
	assert.Equal(t, w.Body.String(), "Mock\n")
}

func TestTracerouteHandlerPostprocess(t *testing.T) {
	setting.tr_bin = "sh"
	setting.tr_flags = []string{"-c", "echo \"first line\n 2 *\nthird line\""}
	setting.tr_raw = false

	r := httptest.NewRequest(http.MethodGet, "/traceroute?q="+url.QueryEscape("1.1.1.1"), nil)
	w := httptest.NewRecorder()
	tracerouteHandler(w, r)
	assert.Equal(t, w.Code, http.StatusOK)
	assert.Equal(t, w.Body.String(), "first line\nthird line\n\n1 hops not responding.")
}

func TestTracerouteHandlerSignatureMissing(t *testing.T) {
	setting.tr_bin = "sh"
	setting.tr_flags = []string{"-c", "echo ok"}
	setting.tr_raw = true

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	setting.ecdsaPublic = &priv.PublicKey
	defer func() { setting.ecdsaPublic = nil }()

	r := httptest.NewRequest(http.MethodGet, "/traceroute?q="+url.QueryEscape("1.1.1.1"), nil)
	w := httptest.NewRecorder()
	tracerouteHandler(w, r)
	assert.Equal(t, w.Code, http.StatusUnauthorized)
}

func TestTracerouteHandlerSignatureValid(t *testing.T) {
	setting.tr_bin = "sh"
	setting.tr_flags = []string{"-c", "echo ok"}
	setting.tr_raw = true

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	setting.ecdsaPublic = &priv.PublicKey
	defer func() { setting.ecdsaPublic = nil }()

	payload := "1.1.1.1"
	sig := signTraceroutePayload(t, priv, payload)

	r := httptest.NewRequest(http.MethodGet, "/traceroute?q="+url.QueryEscape(payload)+"&sig="+url.QueryEscape(sig), nil)
	w := httptest.NewRecorder()
	tracerouteHandler(w, r)
	assert.Equal(t, w.Code, http.StatusOK)
	assert.Equal(t, w.Body.String(), "ok\n")
}
