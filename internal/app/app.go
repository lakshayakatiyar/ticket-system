package app

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type contextKey string

const userIDKey contextKey = "userID"

// User stores only the information needed by this small assignment.
// PasswordHash is never returned in an API response.
type User struct {
	ID           int    `json:"id"`
	Name         string `json:"name,omitempty"`
	Username     string `json:"username,omitempty"`
	Email        string `json:"email,omitempty"`
	PasswordHash string `json:"-"`
}

// Ticket represents a support ticket created by one user.
type Ticket struct {
	ID          int       `json:"id"`
	UserID      int       `json:"user_id"`
	Title       string    `json:"title"`
	Description string    `json:"description,omitempty"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Store is an in-memory data store. A mutex keeps it safe when requests arrive
// at the same time. This is enough for the assignment and keeps the schema simple.
type Store struct {
	mu           sync.RWMutex
	users        map[int]User
	userByEmail  map[string]int
	tickets      map[int]Ticket
	nextUserID   int
	nextTicketID int
}

func newStore() *Store {
	return &Store{
		users:        make(map[int]User),
		userByEmail:  make(map[string]int),
		tickets:      make(map[int]Ticket),
		nextUserID:   1,
		nextTicketID: 1,
	}
}

// App contains the shared state and HTTP routes.
type App struct {
	store     *Store
	jwtSecret []byte
	webPage   string
}

// New creates the complete HTTP handler used by both local Docker and deployment.
func New(webPage string) http.Handler {
	secret := strings.TrimSpace(os.Getenv("JWT_SECRET"))
	if secret == "" {
		// Local fallback keeps the project easy to run. Production deployments
		// should provide JWT_SECRET as an environment variable.
		secret = "eva-bharat-ticket-system-local-secret"
	}

	a := &App{
		store:     newStore(),
		jwtSecret: []byte(secret),
		webPage:   webPage,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", a.handleHome)
	mux.HandleFunc("/health", a.handleHealth)
	mux.HandleFunc("/auth/register", a.handleRegister)
	mux.HandleFunc("/auth/login", a.handleLogin)
	mux.Handle("/tickets", a.auth(http.HandlerFunc(a.handleTickets)))
	mux.Handle("/tickets/", a.auth(http.HandlerFunc(a.handleTicketByID)))
	return logging(mux)
}

func logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		next.ServeHTTP(w, r)
		fmt.Printf("%s %s %s\n", r.Method, r.URL.Path, time.Since(started).Round(time.Millisecond))
	})
}

func (a *App) handleHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		writeError(w, http.StatusNotFound, "route not found")
		return
	}
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(a.webPage))
}

func (a *App) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type registerRequest struct {
	Name     string `json:"name"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (a *App) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req registerRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))
	username := strings.ToLower(strings.TrimSpace(req.Username))
	password := strings.TrimSpace(req.Password)
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = strings.TrimSpace(req.Username)
	}

	if email == "" && username == "" {
		writeError(w, http.StatusBadRequest, "email or username is required")
		return
	}
	if password == "" {
		writeError(w, http.StatusBadRequest, "password is required")
		return
	}

	hash, err := hashPassword(password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not secure password")
		return
	}

	a.store.mu.Lock()
	defer a.store.mu.Unlock()

	if email != "" {
		if _, exists := a.store.userByEmail[email]; exists {
			writeError(w, http.StatusConflict, "user already exists")
			return
		}
	}
	if username != "" {
		if _, exists := a.store.userByEmail[username]; exists {
			writeError(w, http.StatusConflict, "user already exists")
			return
		}
	}

	user := User{
		ID:           a.store.nextUserID,
		Name:         name,
		Username:     username,
		Email:        email,
		PasswordHash: hash,
	}
	a.store.users[user.ID] = user
	if email != "" {
		a.store.userByEmail[email] = user.ID
	}
	if username != "" {
		a.store.userByEmail[username] = user.ID
	}
	a.store.nextUserID++

	writeJSON(w, http.StatusCreated, map[string]any{
		"message": "user registered successfully",
		"user":    user,
	})
}

type loginRequest struct {
	Email    string `json:"email"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req loginRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	identity := strings.ToLower(strings.TrimSpace(req.Email))
	if identity == "" {
		identity = strings.ToLower(strings.TrimSpace(req.Username))
	}
	if identity == "" || strings.TrimSpace(req.Password) == "" {
		writeError(w, http.StatusBadRequest, "email or username and password are required")
		return
	}

	a.store.mu.RLock()
	userID, ok := a.store.userByEmail[identity]
	user := a.store.users[userID]
	a.store.mu.RUnlock()

	if !ok || !verifyPassword(req.Password, user.PasswordHash) {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	token, err := a.createJWT(user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create token")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"token":      token,
		"token_type": "Bearer",
		"expires_in": 86400,
	})
}

type ticketRequest struct {
	Title       string `json:"title"`
	Description string `json:"description"`
}

func (a *App) handleTickets(w http.ResponseWriter, r *http.Request) {
	userID := userIDFromContext(r.Context())

	switch r.Method {
	case http.MethodPost:
		var req ticketRequest
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		title := strings.TrimSpace(req.Title)
		if title == "" {
			writeError(w, http.StatusBadRequest, "title is required")
			return
		}

		now := time.Now().UTC()
		a.store.mu.Lock()
		ticket := Ticket{
			ID:          a.store.nextTicketID,
			UserID:      userID,
			Title:       title,
			Description: strings.TrimSpace(req.Description),
			Status:      "open",
			CreatedAt:   now,
			UpdatedAt:   now,
		}
		a.store.tickets[ticket.ID] = ticket
		a.store.nextTicketID++
		a.store.mu.Unlock()

		writeJSON(w, http.StatusCreated, ticket)

	case http.MethodGet:
		a.store.mu.RLock()
		tickets := make([]Ticket, 0)
		for _, ticket := range a.store.tickets {
			if ticket.UserID == userID {
				tickets = append(tickets, ticket)
			}
		}
		a.store.mu.RUnlock()
		sort.Slice(tickets, func(i, j int) bool { return tickets[i].ID < tickets[j].ID })
		writeJSON(w, http.StatusOK, tickets)

	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (a *App) handleTicketByID(w http.ResponseWriter, r *http.Request) {
	userID := userIDFromContext(r.Context())
	path := strings.TrimPrefix(r.URL.Path, "/tickets/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		writeError(w, http.StatusNotFound, "ticket not found")
		return
	}

	id, err := strconv.Atoi(parts[0])
	if err != nil || id <= 0 {
		writeError(w, http.StatusBadRequest, "invalid ticket id")
		return
	}

	if len(parts) == 1 && r.Method == http.MethodGet {
		a.store.mu.RLock()
		ticket, ok := a.store.tickets[id]
		a.store.mu.RUnlock()
		if !ok || ticket.UserID != userID {
			writeError(w, http.StatusNotFound, "ticket not found")
			return
		}
		writeJSON(w, http.StatusOK, ticket)
		return
	}

	if len(parts) == 2 && parts[1] == "status" && r.Method == http.MethodPatch {
		a.handleStatusUpdate(w, r, id, userID)
		return
	}

	writeError(w, http.StatusMethodNotAllowed, "method not allowed")
}

type statusRequest struct {
	Status string `json:"status"`
}

func (a *App) handleStatusUpdate(w http.ResponseWriter, r *http.Request, ticketID, userID int) {
	var req statusRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	requested := strings.TrimSpace(req.Status)
	if requested != "open" && requested != "in_progress" && requested != "closed" {
		writeError(w, http.StatusBadRequest, "status must be open, in_progress, or closed")
		return
	}

	a.store.mu.Lock()
	defer a.store.mu.Unlock()

	ticket, ok := a.store.tickets[ticketID]
	if !ok || ticket.UserID != userID {
		writeError(w, http.StatusNotFound, "ticket not found")
		return
	}

	if requested == ticket.Status {
		writeJSON(w, http.StatusOK, ticket)
		return
	}

	valid := (ticket.Status == "open" && requested == "in_progress") ||
		(ticket.Status == "in_progress" && requested == "closed")
	if !valid {
		writeError(w, http.StatusConflict, "invalid status transition")
		return
	}

	ticket.Status = requested
	ticket.UpdatedAt = time.Now().UTC()
	a.store.tickets[ticketID] = ticket
	writeJSON(w, http.StatusOK, ticket)
}

func (a *App) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := strings.TrimSpace(r.Header.Get("Authorization"))
		if !strings.HasPrefix(header, "Bearer ") {
			writeError(w, http.StatusUnauthorized, "missing or invalid authorization header")
			return
		}

		token := strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
		userID, err := a.parseJWT(token)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid or expired token")
			return
		}

		a.store.mu.RLock()
		_, exists := a.store.users[userID]
		a.store.mu.RUnlock()
		if !exists {
			writeError(w, http.StatusUnauthorized, "invalid token user")
			return
		}

		ctx := context.WithValue(r.Context(), userIDKey, userID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func userIDFromContext(ctx context.Context) int {
	id, _ := ctx.Value(userIDKey).(int)
	return id
}

type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

type jwtClaims struct {
	Sub string `json:"sub"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
}

func (a *App) createJWT(userID int) (string, error) {
	now := time.Now().Unix()
	headerBytes, err := json.Marshal(jwtHeader{Alg: "HS256", Typ: "JWT"})
	if err != nil {
		return "", err
	}
	claimsBytes, err := json.Marshal(jwtClaims{
		Sub: strconv.Itoa(userID),
		Iat: now,
		Exp: now + 24*60*60,
	})
	if err != nil {
		return "", err
	}

	enc := base64.RawURLEncoding
	signingInput := enc.EncodeToString(headerBytes) + "." + enc.EncodeToString(claimsBytes)
	mac := hmac.New(sha256.New, a.jwtSecret)
	_, _ = mac.Write([]byte(signingInput))
	signature := enc.EncodeToString(mac.Sum(nil))
	return signingInput + "." + signature, nil
}

func (a *App) parseJWT(token string) (int, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return 0, errors.New("invalid token format")
	}

	signingInput := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, a.jwtSecret)
	_, _ = mac.Write([]byte(signingInput))
	expected := mac.Sum(nil)

	provided, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !hmac.Equal(expected, provided) {
		return 0, errors.New("invalid signature")
	}

	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return 0, errors.New("invalid claims")
	}
	var claims jwtClaims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return 0, errors.New("invalid claims")
	}
	if claims.Exp <= time.Now().Unix() {
		return 0, errors.New("token expired")
	}

	userID, err := strconv.Atoi(claims.Sub)
	if err != nil || userID <= 0 {
		return 0, errors.New("invalid subject")
	}
	return userID, nil
}

func decodeJSON(r *http.Request, dst any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	if err := dec.Decode(dst); err != nil {
		return errors.New("invalid JSON body")
	}
	return nil
}

// hashPassword uses PBKDF2-HMAC-SHA256 with a random salt. The stored value
// contains only the algorithm settings, salt, and derived hash - never the password.
func hashPassword(password string) (string, error) {
	const iterations = 100000
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := pbkdf2SHA256([]byte(password), salt, iterations, 32)
	return fmt.Sprintf("pbkdf2_sha256$%d$%s$%s",
		iterations,
		base64.RawURLEncoding.EncodeToString(salt),
		base64.RawURLEncoding.EncodeToString(key),
	), nil
}

func verifyPassword(password, stored string) bool {
	parts := strings.Split(stored, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2_sha256" {
		return false
	}
	iterations, err := strconv.Atoi(parts[1])
	if err != nil || iterations < 1 {
		return false
	}
	salt, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	expected, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		return false
	}
	actual := pbkdf2SHA256([]byte(password), salt, iterations, len(expected))
	return hmac.Equal(actual, expected)
}

// pbkdf2SHA256 is a small local implementation of PBKDF2 using HMAC-SHA256.
func pbkdf2SHA256(password, salt []byte, iterations, keyLen int) []byte {
	const hLen = 32
	blocks := (keyLen + hLen - 1) / hLen
	result := make([]byte, 0, blocks*hLen)

	for block := 1; block <= blocks; block++ {
		mac := hmac.New(sha256.New, password)
		_, _ = mac.Write(salt)
		_, _ = mac.Write([]byte{byte(block >> 24), byte(block >> 16), byte(block >> 8), byte(block)})
		u := mac.Sum(nil)
		t := append([]byte(nil), u...)

		for i := 1; i < iterations; i++ {
			mac = hmac.New(sha256.New, password)
			_, _ = mac.Write(u)
			u = mac.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		result = append(result, t...)
	}
	return result[:keyLen]
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}
