package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/eyupio/zoomies/internal/github"
)

func TestControlRouteQueuesAJobOnTheFake(t *testing.T) {
	fake := github.NewFake()
	defer fake.Close()
	srv := httptest.NewServer(controlHandler(fake))
	defer srv.Close()

	body := `{"repo":"acme/widgets","workflow":"ci","job":"build","labels":["self-hosted","macos"]}`
	resp, err := http.Post(srv.URL+"/jobs", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

func TestControlRouteRefusesAJobWithoutARepository(t *testing.T) {
	fake := github.NewFake()
	defer fake.Close()
	srv := httptest.NewServer(controlHandler(fake))
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/jobs", "application/json", strings.NewReader(`{"workflow":"ci","job":"build"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}
