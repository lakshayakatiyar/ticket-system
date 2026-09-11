package app

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func request(t *testing.T, client *http.Client, method, url, token string, body any) (*http.Response, map[string]any) {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	req, err := http.NewRequest(method, url, &buf)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res, out
}

func TestHealth(t *testing.T) {
	srv := httptest.NewServer(New("ok"))
	defer srv.Close()

	res, err := http.Get(srv.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}
}

func TestFullTicketFlow(t *testing.T) {
	srv := httptest.NewServer(New("ok"))
	defer srv.Close()
	client := srv.Client()

	res, _ := request(t, client, http.MethodPost, srv.URL+"/auth/register", "", map[string]any{
		"name": "Lakshaya", "email": "user@example.com", "password": "secret123",
	})
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("register expected 201, got %d", res.StatusCode)
	}

	res, login := request(t, client, http.MethodPost, srv.URL+"/auth/login", "", map[string]any{
		"email": "user@example.com", "password": "secret123",
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("login expected 200, got %d", res.StatusCode)
	}
	token, _ := login["token"].(string)
	if token == "" {
		t.Fatal("missing token")
	}

	res, ticket := request(t, client, http.MethodPost, srv.URL+"/tickets", token, map[string]any{
		"title": "Test ticket", "description": "Created in test",
	})
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("create ticket expected 201, got %d", res.StatusCode)
	}
	if ticket["status"] != "open" {
		t.Fatalf("expected open status, got %v", ticket["status"])
	}

	res, updated := request(t, client, http.MethodPatch, srv.URL+"/tickets/1/status", token, map[string]any{
		"status": "in_progress",
	})
	if res.StatusCode != http.StatusOK || updated["status"] != "in_progress" {
		t.Fatalf("expected in_progress update, code=%d body=%v", res.StatusCode, updated)
	}

	res, updated = request(t, client, http.MethodPatch, srv.URL+"/tickets/1/status", token, map[string]any{
		"status": "closed",
	})
	if res.StatusCode != http.StatusOK || updated["status"] != "closed" {
		t.Fatalf("expected closed update, code=%d body=%v", res.StatusCode, updated)
	}

	res, _ = request(t, client, http.MethodPatch, srv.URL+"/tickets/1/status", token, map[string]any{
		"status": "open",
	})
	if res.StatusCode != http.StatusConflict {
		t.Fatalf("closed ticket reopened; expected 409, got %d", res.StatusCode)
	}
}

func TestOwnership(t *testing.T) {
	srv := httptest.NewServer(New("ok"))
	defer srv.Close()
	client := srv.Client()

	register := func(email string) string {
		res, _ := request(t, client, http.MethodPost, srv.URL+"/auth/register", "", map[string]any{
			"email": email, "password": "secret123",
		})
		if res.StatusCode != http.StatusCreated {
			t.Fatalf("register failed for %s", email)
		}
		_, login := request(t, client, http.MethodPost, srv.URL+"/auth/login", "", map[string]any{
			"email": email, "password": "secret123",
		})
		token, _ := login["token"].(string)
		return token
	}

	ownerToken := register("owner@example.com")
	otherToken := register("other@example.com")

	res, _ := request(t, client, http.MethodPost, srv.URL+"/tickets", ownerToken, map[string]any{
		"title": "Private ticket",
	})
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("ticket create expected 201, got %d", res.StatusCode)
	}

	res, _ = request(t, client, http.MethodGet, srv.URL+"/tickets/1", otherToken, nil)
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("other user should not access ticket; got %d", res.StatusCode)
	}
}

func TestUsernameOnlyRegistration(t *testing.T) {
	srv := httptest.NewServer(New("ok"))
	defer srv.Close()
	client := srv.Client()

	res, _ := request(t, client, http.MethodPost, srv.URL+"/auth/register", "", map[string]any{
		"username": "lakshaya", "password": "secret123",
	})
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("username register expected 201, got %d", res.StatusCode)
	}

	res, login := request(t, client, http.MethodPost, srv.URL+"/auth/login", "", map[string]any{
		"username": "lakshaya", "password": "secret123",
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("username login expected 200, got %d", res.StatusCode)
	}
	if token, _ := login["token"].(string); token == "" {
		t.Fatal("missing token")
	}
}
