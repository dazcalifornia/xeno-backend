package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"golang.org/x/crypto/bcrypt"
)

type QuoteAPITestSuite struct {
	suite.Suite
	router     *gin.Engine
	testDB     *sql.DB
	testToken  string
	testUserID int
}

func (suite *QuoteAPITestSuite) SetupSuite() {
	// Set gin to test mode
	gin.SetMode(gin.TestMode)

	// Create test database
	var err error
	suite.testDB, err = sql.Open("sqlite3", ":memory:")
	suite.Require().NoError(err)

	// Set global db to test db
	db = suite.testDB

	// Create tables
	createTables()

	// Setup router
	suite.router = gin.New()
	suite.setupRoutes()

	// Create test user and token
	suite.createTestUser()
}

func (suite *QuoteAPITestSuite) TearDownSuite() {
	suite.testDB.Close()
}

func (suite *QuoteAPITestSuite) SetupTest() {
	// Clean up quotes and votes before each test
	suite.testDB.Exec("DELETE FROM votes")
	suite.testDB.Exec("DELETE FROM quotes")
}

func (suite *QuoteAPITestSuite) setupRoutes() {
	suite.router.GET("/health", healthCheck)
	suite.router.POST("/auth/register", register)
	suite.router.POST("/auth/login", login)

	api := suite.router.Group("/api/v1")
	api.Use(authMiddleware())
	{
		api.GET("/users/profile", getUserProfile)
		api.PUT("/users/profile", updateUserProfile)
		api.GET("/quotes", listQuotes)
		api.GET("/quotes/:id", getQuote)
		api.POST("/quotes", createQuote)
		api.PUT("/quotes/:id", updateQuote)
		api.DELETE("/quotes/:id", deleteQuote)
		api.POST("/votes", voteHandler)
		api.GET("/votes/my-vote", getMyVotes)
	}
}

func (suite *QuoteAPITestSuite) createTestUser() {
	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("testpass123"), bcrypt.DefaultCost)
	suite.Require().NoError(err)

	// Insert test user
	result, err := suite.testDB.Exec("INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
		"Test User", "test@example.com", string(hashedPassword))
	suite.Require().NoError(err)

	userID, err := result.LastInsertId()
	suite.Require().NoError(err)
	suite.testUserID = int(userID)

	// Create JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims{
		UserID: suite.testUserID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	})

	tokenString, err := token.SignedString(jwtSecret)
	suite.Require().NoError(err)
	suite.testToken = tokenString
}

func (suite *QuoteAPITestSuite) makeRequest(method, url string, body interface{}, token string) *httptest.ResponseRecorder {
	var bodyBytes []byte
	if body != nil {
		bodyBytes, _ = json.Marshal(body)
	}

	// Ensure URL is properly formatted
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		// For relative URLs, just ensure they start with /
		if !strings.HasPrefix(url, "/") {
			url = "/" + url
		}
	}

	req, err := http.NewRequest(method, url, bytes.NewBuffer(bodyBytes))
	if err != nil {
		suite.T().Fatalf("Failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	w := httptest.NewRecorder()
	suite.router.ServeHTTP(w, req)
	return w
}

// Test Health Check
func (suite *QuoteAPITestSuite) TestHealthCheck() {
	w := suite.makeRequest("GET", "/health", nil, "")

	assert.Equal(suite.T(), http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), "healthy", response["status"])
}

// Test User Registration
func (suite *QuoteAPITestSuite) TestRegister() {
	// Test successful registration
	registerReq := RegisterRequest{
		Name:     "New User",
		Email:    "newuser@example.com",
		Password: "password123",
	}

	w := suite.makeRequest("POST", "/auth/register", registerReq, "")
	assert.Equal(suite.T(), http.StatusCreated, w.Code)

	var response APIResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(suite.T(), err)
	assert.True(suite.T(), response.Success)
	assert.Equal(suite.T(), "User registered successfully", response.Message)

	// Test duplicate email
	w = suite.makeRequest("POST", "/auth/register", registerReq, "")
	assert.Equal(suite.T(), http.StatusConflict, w.Code)

	err = json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(suite.T(), err)
	assert.False(suite.T(), response.Success)
	assert.Equal(suite.T(), "Email already registered", response.Message)

	// Test invalid request (missing required fields)
	invalidReq := RegisterRequest{
		Name: "Test",
		// Missing email and password
	}

	w = suite.makeRequest("POST", "/auth/register", invalidReq, "")
	assert.Equal(suite.T(), http.StatusBadRequest, w.Code)
}

// Test User Login
func (suite *QuoteAPITestSuite) TestLogin() {
	// Test successful login
	loginReq := LoginRequest{
		Email:    "test@example.com",
		Password: "testpass123",
	}

	w := suite.makeRequest("POST", "/auth/login", loginReq, "")
	assert.Equal(suite.T(), http.StatusOK, w.Code)

	var response APIResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(suite.T(), err)
	assert.True(suite.T(), response.Success)
	assert.Equal(suite.T(), "Login successful", response.Message)

	// Check if token is present in response
	data := response.Data.(map[string]interface{})
	assert.NotEmpty(suite.T(), data["token"])

	// Test invalid credentials
	invalidLoginReq := LoginRequest{
		Email:    "test@example.com",
		Password: "wrongpassword",
	}

	w = suite.makeRequest("POST", "/auth/login", invalidLoginReq, "")
	assert.Equal(suite.T(), http.StatusUnauthorized, w.Code)

	err = json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(suite.T(), err)
	assert.False(suite.T(), response.Success)
	assert.Equal(suite.T(), "Invalid credentials", response.Message)
}

// Test Get User Profile
func (suite *QuoteAPITestSuite) TestGetUserProfile() {
	// Test with valid token
	w := suite.makeRequest("GET", "/api/v1/users/profile", nil, suite.testToken)
	assert.Equal(suite.T(), http.StatusOK, w.Code)

	var response APIResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(suite.T(), err)
	assert.True(suite.T(), response.Success)

	// Test without token
	w = suite.makeRequest("GET", "/api/v1/users/profile", nil, "")
	assert.Equal(suite.T(), http.StatusUnauthorized, w.Code)

	// Test with invalid token
	w = suite.makeRequest("GET", "/api/v1/users/profile", nil, "invalid-token")
	assert.Equal(suite.T(), http.StatusUnauthorized, w.Code)
}

// Test Update User Profile
func (suite *QuoteAPITestSuite) TestUpdateUserProfile() {
	updateReq := map[string]string{
		"name": "Updated Name",
	}

	w := suite.makeRequest("PUT", "/api/v1/users/profile", updateReq, suite.testToken)
	assert.Equal(suite.T(), http.StatusOK, w.Code)

	var response APIResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(suite.T(), err)
	assert.True(suite.T(), response.Success)
	assert.Equal(suite.T(), "Profile updated successfully", response.Message)

	// Verify the update in database
	var name string
	err = suite.testDB.QueryRow("SELECT name FROM users WHERE id = ?", suite.testUserID).Scan(&name)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), "Updated Name", name)
}

// Test Create Quote
func (suite *QuoteAPITestSuite) TestCreateQuote() {
	quoteReq := QuoteRequest{
		Quote: "This is a test quote",
	}

	w := suite.makeRequest("POST", "/api/v1/quotes", quoteReq, suite.testToken)
	assert.Equal(suite.T(), http.StatusCreated, w.Code)

	var response APIResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(suite.T(), err)
	assert.True(suite.T(), response.Success)
	assert.Equal(suite.T(), "Quote created successfully", response.Message)

	// Test without token
	w = suite.makeRequest("POST", "/api/v1/quotes", quoteReq, "")
	assert.Equal(suite.T(), http.StatusUnauthorized, w.Code)

	// Test with empty quote
	emptyQuoteReq := QuoteRequest{
		Quote: "",
	}
	w = suite.makeRequest("POST", "/api/v1/quotes", emptyQuoteReq, suite.testToken)
	assert.Equal(suite.T(), http.StatusBadRequest, w.Code)
}

// Test List Quotes
func (suite *QuoteAPITestSuite) TestListQuotes() {
	// Create test quotes
	suite.testDB.Exec("INSERT INTO quotes (quote, author_id) VALUES (?, ?)", "Quote 1", suite.testUserID)
	suite.testDB.Exec("INSERT INTO quotes (quote, author_id) VALUES (?, ?)", "Quote 2", suite.testUserID)

	// Test basic listing
	w := suite.makeRequest("GET", "/api/v1/quotes", nil, suite.testToken)
	assert.Equal(suite.T(), http.StatusOK, w.Code)

	var response APIResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(suite.T(), err)
	assert.True(suite.T(), response.Success)

	// Test with pagination
	w = suite.makeRequest("GET", "/api/v1/quotes?page=1&page_size=1", nil, suite.testToken)
	assert.Equal(suite.T(), http.StatusOK, w.Code)

	// Test with search (URL encode the space)
	w = suite.makeRequest("GET", "/api/v1/quotes?search=Quote+1", nil, suite.testToken)
	assert.Equal(suite.T(), http.StatusOK, w.Code)

	// Test with sorting
	w = suite.makeRequest("GET", "/api/v1/quotes?sort_by=vote_count&sort_order=asc", nil, suite.testToken)
	assert.Equal(suite.T(), http.StatusOK, w.Code)
}

// Test Get Single Quote
func (suite *QuoteAPITestSuite) TestGetQuote() {
	// Create test quote
	result, err := suite.testDB.Exec("INSERT INTO quotes (quote, author_id) VALUES (?, ?)", "Test Quote", suite.testUserID)
	suite.Require().NoError(err)
	quoteID, _ := result.LastInsertId()

	// Test get existing quote
	w := suite.makeRequest("GET", fmt.Sprintf("/api/v1/quotes/%d", quoteID), nil, suite.testToken)
	assert.Equal(suite.T(), http.StatusOK, w.Code)

	var response APIResponse
	err = json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(suite.T(), err)
	assert.True(suite.T(), response.Success)

	// Test get non-existent quote
	w = suite.makeRequest("GET", "/api/v1/quotes/99999", nil, suite.testToken)
	assert.Equal(suite.T(), http.StatusNotFound, w.Code)

	// Test with invalid ID
	w = suite.makeRequest("GET", "/api/v1/quotes/invalid", nil, suite.testToken)
	assert.Equal(suite.T(), http.StatusBadRequest, w.Code)
}

// Test Update Quote
func (suite *QuoteAPITestSuite) TestUpdateQuote() {
	// Create test quote
	result, err := suite.testDB.Exec("INSERT INTO quotes (quote, author_id) VALUES (?, ?)", "Original Quote", suite.testUserID)
	suite.Require().NoError(err)
	quoteID, _ := result.LastInsertId()

	// Test successful update
	updateReq := QuoteRequest{
		Quote: "Updated Quote",
	}

	w := suite.makeRequest("PUT", fmt.Sprintf("/api/v1/quotes/%d", quoteID), updateReq, suite.testToken)
	assert.Equal(suite.T(), http.StatusOK, w.Code)

	var response APIResponse
	err = json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(suite.T(), err)
	assert.True(suite.T(), response.Success)

	// Create quote with votes (should not be updatable)
	result2, err := suite.testDB.Exec("INSERT INTO quotes (quote, author_id, vote_count) VALUES (?, ?, ?)", "Voted Quote", suite.testUserID, 1)
	suite.Require().NoError(err)
	votedQuoteID, _ := result2.LastInsertId()

	w = suite.makeRequest("PUT", fmt.Sprintf("/api/v1/quotes/%d", votedQuoteID), updateReq, suite.testToken)
	assert.Equal(suite.T(), http.StatusBadRequest, w.Code)
}

// Test Delete Quote
func (suite *QuoteAPITestSuite) TestDeleteQuote() {
	// Create test quote
	result, err := suite.testDB.Exec("INSERT INTO quotes (quote, author_id) VALUES (?, ?)", "Quote to Delete", suite.testUserID)
	suite.Require().NoError(err)
	quoteID, _ := result.LastInsertId()

	// Test successful deletion
	w := suite.makeRequest("DELETE", fmt.Sprintf("/api/v1/quotes/%d", quoteID), nil, suite.testToken)
	assert.Equal(suite.T(), http.StatusOK, w.Code)

	var response APIResponse
	err = json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(suite.T(), err)
	assert.True(suite.T(), response.Success)

	// Verify deletion
	var count int
	err = suite.testDB.QueryRow("SELECT COUNT(*) FROM quotes WHERE id = ?", quoteID).Scan(&count)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), 0, count)

	// Test delete non-existent quote
	w = suite.makeRequest("DELETE", "/api/v1/quotes/99999", nil, suite.testToken)
	assert.Equal(suite.T(), http.StatusNotFound, w.Code)
}

// Test Vote Handler
func (suite *QuoteAPITestSuite) TestVoteHandler() {
	// Create test quote
	result, err := suite.testDB.Exec("INSERT INTO quotes (quote, author_id) VALUES (?, ?)", "Quote to Vote", suite.testUserID)
	suite.Require().NoError(err)
	quoteID, _ := result.LastInsertId()

	// Test successful vote
	voteReq := VoteRequest{
		QuoteID: int(quoteID),
		Action:  "vote",
	}

	w := suite.makeRequest("POST", "/api/v1/votes", voteReq, suite.testToken)
	assert.Equal(suite.T(), http.StatusOK, w.Code)

	var response APIResponse
	err = json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(suite.T(), err)
	assert.True(suite.T(), response.Success)

	// Verify vote count updated
	var voteCount int
	err = suite.testDB.QueryRow("SELECT vote_count FROM quotes WHERE id = ?", quoteID).Scan(&voteCount)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), 1, voteCount)

	// Test double voting (should fail)
	w = suite.makeRequest("POST", "/api/v1/votes", voteReq, suite.testToken)
	assert.Equal(suite.T(), http.StatusBadRequest, w.Code)

	// Test unvote
	unvoteReq := VoteRequest{
		QuoteID: int(quoteID),
		Action:  "unvote",
	}

	w = suite.makeRequest("POST", "/api/v1/votes", unvoteReq, suite.testToken)
	assert.Equal(suite.T(), http.StatusOK, w.Code)

	// Verify vote count decreased
	err = suite.testDB.QueryRow("SELECT vote_count FROM quotes WHERE id = ?", quoteID).Scan(&voteCount)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), 0, voteCount)

	// Test invalid action
	invalidVoteReq := VoteRequest{
		QuoteID: int(quoteID),
		Action:  "invalid",
	}

	w = suite.makeRequest("POST", "/api/v1/votes", invalidVoteReq, suite.testToken)
	assert.Equal(suite.T(), http.StatusBadRequest, w.Code)
}

// Test Get My Votes
func (suite *QuoteAPITestSuite) TestGetMyVotes() {
	// Create test quote and vote
	result, err := suite.testDB.Exec("INSERT INTO quotes (quote, author_id) VALUES (?, ?)", "Voted Quote", suite.testUserID)
	suite.Require().NoError(err)
	quoteID, _ := result.LastInsertId()

	// Add vote
	suite.testDB.Exec("INSERT INTO votes (user_id, quote_id, user_agent, ip_address) VALUES (?, ?, ?, ?)",
		suite.testUserID, quoteID, "test-agent", "127.0.0.1")
	suite.testDB.Exec("UPDATE quotes SET vote_count = 1 WHERE id = ?", quoteID)

	// Test get my votes
	w := suite.makeRequest("GET", "/api/v1/votes/my-vote", nil, suite.testToken)
	assert.Equal(suite.T(), http.StatusOK, w.Code)

	var response APIResponse
	err = json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(suite.T(), err)
	assert.True(suite.T(), response.Success)

	data := response.Data.(map[string]interface{})
	votes := data["votes"].([]interface{})
	assert.Len(suite.T(), votes, 1)
}

// Test Authentication Middleware
func (suite *QuoteAPITestSuite) TestAuthMiddleware() {
	// Test missing authorization header
	w := suite.makeRequest("GET", "/api/v1/users/profile", nil, "")
	assert.Equal(suite.T(), http.StatusUnauthorized, w.Code)

	// Test invalid token format
	w = suite.makeRequest("GET", "/api/v1/users/profile", nil, "InvalidToken")
	assert.Equal(suite.T(), http.StatusUnauthorized, w.Code)

	// Test expired token
	expiredToken := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims{
		UserID: suite.testUserID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)), // Expired
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
		},
	})
	expiredTokenString, _ := expiredToken.SignedString(jwtSecret)

	w = suite.makeRequest("GET", "/api/v1/users/profile", nil, expiredTokenString)
	assert.Equal(suite.T(), http.StatusUnauthorized, w.Code)
}

// Test Permission Checks
func (suite *QuoteAPITestSuite) TestPermissions() {
	// Create another user
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("testpass123"), bcrypt.DefaultCost)
	result, err := suite.testDB.Exec("INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
		"Other User", "other@example.com", string(hashedPassword))
	suite.Require().NoError(err)
	otherUserID, _ := result.LastInsertId()

	// Create token for other user
	otherToken := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims{
		UserID: int(otherUserID),
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	})
	otherTokenString, _ := otherToken.SignedString(jwtSecret)

	// Create quote by first user
	result, err = suite.testDB.Exec("INSERT INTO quotes (quote, author_id) VALUES (?, ?)", "My Quote", suite.testUserID)
	suite.Require().NoError(err)
	quoteID, _ := result.LastInsertId()

	// Try to update other user's quote (should fail)
	updateReq := QuoteRequest{
		Quote: "Hacked Quote",
	}

	w := suite.makeRequest("PUT", fmt.Sprintf("/api/v1/quotes/%d", quoteID), updateReq, otherTokenString)
	assert.Equal(suite.T(), http.StatusForbidden, w.Code)

	// Try to delete other user's quote (should fail)
	w = suite.makeRequest("DELETE", fmt.Sprintf("/api/v1/quotes/%d", quoteID), nil, otherTokenString)
	assert.Equal(suite.T(), http.StatusForbidden, w.Code)
}

func TestQuoteAPITestSuite(t *testing.T) {
	suite.Run(t, new(QuoteAPITestSuite))
}

// Additional benchmark tests
func BenchmarkListQuotes(b *testing.B) {
	// Setup
	gin.SetMode(gin.TestMode)
	testDB, _ := sql.Open("sqlite3", ":memory:")
	defer testDB.Close()

	db = testDB
	createTables()

	// Create test data
	for i := 0; i < 100; i++ {
		testDB.Exec("INSERT INTO quotes (quote, author_id) VALUES (?, ?)",
			fmt.Sprintf("Quote %d", i), 1)
	}

	router := gin.New()
	router.GET("/quotes", func(c *gin.Context) {
		c.Set("user_id", 1)
		listQuotes(c)
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/quotes", nil)
		router.ServeHTTP(w, req)
	}
}

// Helper function to run individual tests
func TestMain(m *testing.M) {
	// Setup
	gin.SetMode(gin.TestMode)

	// Run tests
	code := m.Run()

	// Cleanup
	os.Exit(code)
}
