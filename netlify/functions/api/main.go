package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/awslabs/aws-lambda-go-api-proxy/httpadapter" // Corrected import
	"github.com/gorilla/securecookie"
	// Note: We don't need godotenv, Netlify injects env vars directly
)

// --- Configuration ---
// These are loaded from Netlify environment variables
var (
	oktaDomain     string
	oktaApiToken   string
	cookieHashKey  []byte
	cookieBlockKey []byte
)

var s *securecookie.SecureCookie
var httpAdapter *httpadapter.HandlerAdapter

// --- Constants ---
const (
	sessionCookieName = "okta-tx-session"
	csrfCookieName    = "XSRF-TOKEN"
	csrfHeaderName    = "X-CSRF-TOKEN"
)

// --- Okta API Response Structs ---
type OktaUser struct {
	ID      string          `json:"id"`
	Profile OktaUserProfile `json:"profile"`
}
type OktaUserProfile struct {
	Email string `json:"email"`
	Login string `json:"login"`
}
type OktaFactor struct {
	ID         string `json:"id"`
	FactorType string `json:"factorType"`
	Provider   string `json:"provider"`
	Status     string `json:"status"`
}

// --- Request/Response Structs for our API ---
type GetUserRequest struct {
	Email string `json:"email"`
}
type FactorResponse struct {
	FactorID   string `json:"factorId"`
	FactorType string `json:"factorType"`
	Provider   string `json:"provider"`
}
type ChallengeRequest struct {
	FactorID string `json:"factorId"`
}
type VerifyRequest struct {
	FactorID string `json:"factorId"`
	PassCode string `json:"passCode"`
}
type VerifyResponse struct {
	Username string `json:"username"`
}

// --- Initialization ---
// init() runs once when the serverless function starts (cold start)
func init() {
	// Load configuration from environment variables
	oktaDomain = os.Getenv("OKTA_DOMAIN")
	if oktaDomain == "" {
		log.Fatal("OKTA_DOMAIN environment variable is not set")
	}

	oktaApiToken = os.Getenv("OKTA_API_TOKEN")
	if oktaApiToken == "" {
		log.Fatal("OKTA_API_TOKEN environment variable is not set")
	}

	hashKeyStr := os.Getenv("COOKIE_HASH_KEY")
	if hashKeyStr == "" {
		log.Fatal("COOKIE_HASH_KEY is not set.")
	}
	var err error
	cookieHashKey, err = hex.DecodeString(hashKeyStr)
	if err != nil {
		log.Fatalf("Failed to decode COOKIE_HASH_KEY: %v.", err)
	}
	if len(cookieHashKey) != 64 {
		log.Printf("Warning: COOKIE_HASH_KEY length is %d bytes, expected 64.", len(cookieHashKey))
	}

	blockKeyStr := os.Getenv("COOKIE_BLOCK_KEY")
	if blockKeyStr == "" {
		log.Fatal("COOKIE_BLOCK_KEY is not set.")
	}
	cookieBlockKey, err = hex.DecodeString(blockKeyStr)
	if err != nil {
		log.Fatalf("Failed to decode COOKIE_BLOCK_KEY: %v.", err)
	}
	if len(cookieBlockKey) != 32 {
		log.Fatalf("Invalid COOKIE_BLOCK_KEY length: got %d bytes, expected 32.", len(cookieBlockKey))
	}

	// Initialize secure cookie handler
	s = securecookie.New(cookieHashKey, cookieBlockKey)
	s.MaxAge(300) // 5 minute session

	// --- Set up the HTTP router ---
	// This is the logic that used to be in main()
	mux := http.NewServeMux()

	// API Endpoints
	mux.HandleFunc("/api/init", handleInit)
	mux.Handle("/api/get-user-and-factors", csrfMiddleware(http.HandlerFunc(handleGetUserAndFactors)))
	mux.Handle("/api/challenge-factor", csrfMiddleware(http.HandlerFunc(handleChallengeFactor)))
	mux.Handle("/api/verify-factor", csrfMiddleware(http.HandlerFunc(handleVerifyFactor)))
	mux.Handle("/api/redirect-to-okta", csrfMiddleware(http.HandlerFunc(redirectToOktaSignPage)))

	// --- Create the adapter ---
	// This adapter converts Lambda events into standard Go http.Requests
	httpAdapter = httpadapter.New(mux)
}

// --- Lambda Handler ---
// This is the new entry point for all requests.
func Handler(ctx context.Context, req events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	// The adapter does all the work of routing to your mux
	return httpAdapter.ProxyWithContext(ctx, req)
}

// --- Main Function ---
// This starts the Lambda listener
func main() {
	lambda.Start(Handler)
}

// --- Okta API Helper Functions ---
// (All helper functions below are identical to your original main.go)

func oktaApiRequest(method, path string, body io.Reader) (*http.Response, error) {
	// The path from the router will include /api/, but the Okta API doesn't want that.
	// We need to strip the /api prefix before sending to Okta.
	// But wait, the path we're given (e.g., "users") doesn't have /api/.
	// Let's check... ah, the handlers (e.g., getUserIdByEmail) construct the path
	// like "users?search=%s". This is correct. No change needed here.

	url := fmt.Sprintf("https://%s/api/v1/%s", oktaDomain, path)
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "SSWS "+oktaApiToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	log.Printf("Okta API Request URL: %s %s", method, req.URL.String())
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Okta API Error: %v", err)
	} else {
		log.Printf("Okta API Response Status: %s", resp.Status)
	}
	return resp, err
}

func getUserIdByEmail(email string) (string, error) {
	searchValue := fmt.Sprintf(`profile.email eq "%s"`, email)
	encodedSearchValue := url.QueryEscape(searchValue)
	path := fmt.Sprintf("users?search=%s", encodedSearchValue)

	resp, err := oktaApiRequest(http.MethodGet, path, nil)
	if err != nil {
		return "", fmt.Errorf("request to Okta failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		log.Printf("Okta API Error Body: %s", string(bodyBytes))
		return "", fmt.Errorf("okta API returned status %d", resp.StatusCode)
	}

	var users []OktaUser
	if err := json.NewDecoder(resp.Body).Decode(&users); err != nil {
		return "", fmt.Errorf("failed to decode Okta user response: %v", err)
	}

	log.Printf("Found %d user(s) for email %s", len(users), email)
	if len(users) == 0 {
		return "", fmt.Errorf("user not found")
	}
	return users[0].ID, nil
}

func getUserFactors(userId string) ([]FactorResponse, error) {
	path := fmt.Sprintf("users/%s/factors", userId)
	resp, err := oktaApiRequest(http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("request to Okta failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		log.Printf("Okta API Error Body: %s", string(bodyBytes))
		return nil, fmt.Errorf("okta API returned status %d", resp.StatusCode)
	}

	var factors []OktaFactor
	if err := json.NewDecoder(resp.Body).Decode(&factors); err != nil {
		return nil, fmt.Errorf("failed to decode Okta factors: %v", err)
	}

	var responseFactors []FactorResponse
	for _, f := range factors {
		if f.Status == "ACTIVE" {
			if f.FactorType == "sms" || f.FactorType == "call" || f.FactorType == "token:software:totp" {
				responseFactors = append(responseFactors, FactorResponse{
					FactorID:   f.ID,
					FactorType: f.FactorType,
					Provider:   f.Provider,
				})
			}
		}
	}

	log.Printf("Found %d suitable factors for user %s", len(responseFactors), userId)
	if len(responseFactors) == 0 {
		return nil, fmt.Errorf("no suitable MFA factors found for user")
	}
	return responseFactors, nil
}

func challengeFactor(userId, factorId string) error {
	path := fmt.Sprintf("users/%s/factors/%s/verify", userId, factorId)
	resp, err := oktaApiRequest(http.MethodPost, path, nil)
	if err != nil {
		return fmt.Errorf("request to Okta failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		log.Printf("Okta API Error Body: %s", string(bodyBytes))
		return fmt.Errorf("okta API returned status %d while challenging", resp.StatusCode)
	}
	return nil
}

func verifyFactor(userId, factorId, passCode string) (bool, error) {
	path := fmt.Sprintf("users/%s/factors/%s/verify", userId, factorId)
	body := fmt.Sprintf(`{"passCode": "%s"}`, passCode)

	resp, err := oktaApiRequest(http.MethodPost, path, bytes.NewBufferString(body))
	if err != nil {
		return false, fmt.Errorf("request to Okta failed: %v", err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	log.Printf("Okta Verify Response Body: %s", string(bodyBytes))

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("verification failed with status: %s", resp.Status)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &result); err != nil {
		return false, fmt.Errorf("failed to decode verification response: %v", err)
	}

	if status, ok := result["factorResult"].(string); ok && status == "SUCCESS" {
		return true, nil
	}
	return false, fmt.Errorf("verification failed")
}

func getOktaUser(userId string) (*OktaUser, error) {
	path := fmt.Sprintf("users/%s", userId)
	resp, err := oktaApiRequest(http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("request to Okta failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		log.Printf("Okta API Error Body: %s", string(bodyBytes))
		return nil, fmt.Errorf("okta API returned status %d", resp.StatusCode)
	}

	var user OktaUser
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, fmt.Errorf("failed to decode Okta user: %v", err)
	}
	return &user, nil
}

// --- HTTP Handlers ---
// (All handlers below are identical to your original main.go)

func httpError(w http.ResponseWriter, message string, code int) {
	log.Println("Error:", message)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func handleGetUserAndFactors(w http.ResponseWriter, r *http.Request) {
	log.Println("Handling /api/get-user-and-factors request")
	var req GetUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if req.Email == "" {
		httpError(w, "Email is required", http.StatusBadRequest)
		return
	}

	userId, err := getUserIdByEmail(req.Email)
	if err != nil {
		httpError(w, err.Error(), http.StatusNotFound)
		return
	}
	factors, err := getUserFactors(userId)
	if err != nil {
		httpError(w, err.Error(), http.StatusNotFound)
		return
	}

	sessionData := map[string]string{"userId": userId}
	if encoded, err := s.Encode(sessionCookieName, sessionData); err == nil {
		cookie := &http.Cookie{
			Name:     sessionCookieName,
			Value:    encoded,
			Path:     "/", // Important: Set path to /
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   300, // 5 minutes
		}
		// Note: We can't use http.SetCookie. We must return the header.
		// The aws-lambda-go-api-proxy handles this for us.
		http.SetCookie(w, cookie)
	} else {
		httpError(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(factors)
}

func handleChallengeFactor(w http.ResponseWriter, r *http.Request) {
	var sessionData map[string]string
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		httpError(w, "Session not found or expired", http.StatusUnauthorized)
		return
	}
	if err := s.Decode(sessionCookieName, cookie.Value, &sessionData); err != nil {
		httpError(w, "Invalid session", http.StatusUnauthorized)
		return
	}
	userId := sessionData["userId"]

	var req ChallengeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if req.FactorID == "" {
		httpError(w, "FactorID is required", http.StatusBadRequest)
		return
	}

	if err := challengeFactor(userId, req.FactorID); err != nil {
		httpError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "challenge_sent"})
}

func handleVerifyFactor(w http.ResponseWriter, r *http.Request) {
	var sessionData map[string]string
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		httpError(w, "Session not found or expired", http.StatusUnauthorized)
		return
	}
	if err := s.Decode(sessionCookieName, cookie.Value, &sessionData); err != nil {
		httpError(w, "Invalid session", http.StatusUnauthorized)
		return
	}
	userId := sessionData["userId"]

	var req VerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if req.FactorID == "" || req.PassCode == "" {
		httpError(w, "FactorID and PassCode are required", http.StatusBadRequest)
		return
	}

	success, err := verifyFactor(userId, req.FactorID, req.PassCode)
	if !success || err != nil {
		httpError(w, "Verification failed", http.StatusUnauthorized)
		return
	}

	user, err := getOktaUser(userId)
	if err != nil {
		httpError(w, "Could not retrieve user details", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1, // Delete cookie
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(VerifyResponse{Username: user.Profile.Login})
}

func redirectToOktaSignPage(w http.ResponseWriter, r *http.Request) {

	// Invalidate the session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1, // Delete cookie
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	// Redirect to Okta sign-in page
	redirectURL := fmt.Sprintf("https://%s", oktaDomain)
	http.Redirect(w, r, redirectURL, http.StatusFound)

}

// --- Security Middleware ---
func csrfMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(csrfCookieName)
		if err != nil {
			httpError(w, "CSRF cookie not found", http.StatusForbidden)
			return
		}
		cookieToken := cookie.Value
		headerToken := r.Header.Get(csrfHeaderName)
		if headerToken == "" {
			httpError(w, "CSRF header not found", http.StatusForbidden)
			return
		}
		if cookieToken != headerToken {
			httpError(w, "Invalid CSRF token", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func handleInit(w http.ResponseWriter, r *http.Request) {
	b := make([]byte, 32)
	rand.Read(b)
	token := hex.EncodeToString(b)

	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   300, // 5 minutes
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "XSRF-TOKEN-JS",
		Value:    token,
		Path:     "/",
		HttpOnly: false,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   300, // 5 minutes
	})

	w.WriteHeader(http.StatusOK)
}
