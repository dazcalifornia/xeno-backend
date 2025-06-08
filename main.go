package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

var (
	db        *sql.DB
	jwtSecret = []byte("4d2dc0863ada763cbc46c744d2c2212e0b36d0086a2e85fab748befbf30dfd81a94e2ef0a025464d12b705fb374135474b2203982a9c3e54dc6aff2264f46cab84f6d6e8c4b9eed20c58a32079d008fa1f3821f5c8355f650c2f50dd5f59feba7b4aeb0e1b682a6a1d13bc4b6a92f11cf38994085e90503066a85562b1286dae477e5f615d99e9753db7c0c7cb36dc2ff92916571884d8baa2ad96e90a31459dba74cf7ffcc3310849274bfed6a1cc9ecf60f7901d516cd6a6bab51b94ac4bffcf221dbf120601c4b53f8c57701eb35c00dd8f4810a7f8dd6faaf7b2375098e118fc3f47ef632f3b20732b045015b699cb05289057e48df82425dbe1e1d68c5a")
)

type User struct {
	ID       int    `json:"id" db:"id"`
	Name     string `json:"name" db:"name"`
	Email    string `json:"email" db:"email"`
	Password string `json:"-" db:"password"`
}

type Quote struct {
	ID         int       `json:"id" db:"id"`
	Quote      string    `json:"quote" db:"quote"`
	AuthorID   int       `json:"author_id" db:"author_id"`
	AuthorName string    `json:"author_name,omitempty"`
	VoteCount  int       `json:"vote_count" db:"vote_count"`
	CreatedAt  time.Time `json:"created_at" db:"created_at"`
	UpdatedAt  time.Time `json:"updated_at" db:"updated_at"`
	CanBeVoted bool      `json:"can_be_voted"`
	UserVoted  bool      `json:"user_voted,omitempty"`
}

type Vote struct {
	ID        int       `json:"id" db:"id"`
	UserID    int       `json:"user_id" db:"user_id"`
	QuoteID   int       `json:"quote_id" db:"quote_id"`
	UserAgent string    `json:"user_agent" db:"user_agent"`
	IPAddress string    `json:"ip_address" db:"ip_address"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

type LoginRequest struct {
	Email    string `json:"email" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type RegisterRequest struct {
	Name     string `json:"name" binding:"required"`
	Email    string `json:"email" binding:"required"`
	Password string `json:"password" binding:"required,min=6"`
}

type QuoteRequest struct {
	Quote string `json:"quote" binding:"required"`
}

type VoteRequest struct {
	QuoteID int    `json:"quote_id" binding:"required"`
	Action  string `json:"action" binding:"required"`
}

type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

type QuoteListResponse struct {
	Quotes     []Quote `json:"quotes"`
	TotalCount int     `json:"total_count"`
	Page       int     `json:"page"`
	PageSize   int     `json:"page_size"`
	TotalPages int     `json:"total_pages"`
}

type Claims struct {
	UserID int `json:"user_id"`
	jwt.RegisteredClaims
}

func main() {
	initDB()
	defer db.Close()

	gin.SetMode(gin.ReleaseMode)
	router := gin.Default()
	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowHeaders:     []string{"Authorization", "Content-Type"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE"},
		AllowCredentials: true,
	}))

	router.GET("/health", healthCheck)
	router.POST("/auth/register", register)
	router.POST("/auth/login", login)

	api := router.Group("/api/v1")
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

	log.Println("Server starting on :9912")
	router.Run(":9912")
}

func initDB() {
	var err error
	db, err = sql.Open("sqlite3", "./quotes.db")
	if err != nil {
		log.Fatal("Failed to open database:", err)
	}

	createTables()
}

func createTables() {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			email TEXT UNIQUE NOT NULL,
			password TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS quotes (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			quote TEXT NOT NULL,
			author_id INTEGER NOT NULL,
			vote_count INTEGER DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (author_id) REFERENCES users(id)
		)`,
		`CREATE TABLE IF NOT EXISTS votes (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			quote_id INTEGER NOT NULL,
			user_agent TEXT,
			ip_address TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id),
			FOREIGN KEY (quote_id) REFERENCES quotes(id),
			UNIQUE(user_id, quote_id)
		)`,
	}

	for _, query := range queries {
		_, err := db.Exec(query)
		if err != nil {
			log.Fatal("Failed to create table:", err)
		}
	}
}

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		println("auth", authHeader)
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, APIResponse{
				Success: false,
				Message: "Authorization header required",
			})
			c.Abort()
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			c.JSON(http.StatusUnauthorized, APIResponse{
				Success: false,
				Message: "Bearer token required",
			})
			c.Abort()
			return
		}

		token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, APIResponse{
				Success: false,
				Message: "Invalid token",
			})
			c.Abort()
			return
		}

		claims, ok := token.Claims.(*Claims)
		if !ok {
			c.JSON(http.StatusUnauthorized, APIResponse{
				Success: false,
				Message: "Invalid token claims",
			})
			c.Abort()
			return
		}

		c.Set("user_id", claims.UserID)
		c.Next()
	}
}

func healthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":  "healthy",
		"message": "API is running",
	})
}

func register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Message: err.Error(),
		})
		return
	}

	var exists bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE email = ?)", req.Email).Scan(&exists)
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Message: "Database error",
		})
		return
	}

	if exists {
		c.JSON(http.StatusConflict, APIResponse{
			Success: false,
			Message: "Email already registered",
		})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Message: "Failed to hash password",
		})
		return
	}

	result, err := db.Exec("INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
		req.Name, req.Email, string(hashedPassword))
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Message: "Failed to create user",
		})
		return
	}

	userID, _ := result.LastInsertId()

	c.JSON(http.StatusCreated, APIResponse{
		Success: true,
		Message: "User registered successfully",
		Data: gin.H{
			"user_id": userID,
			"name":    req.Name,
			"email":   req.Email,
		},
	})
}

func login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Message: err.Error(),
		})
		return
	}

	var user User
	err := db.QueryRow("SELECT id, name, email, password FROM users WHERE email = ?", req.Email).
		Scan(&user.ID, &user.Name, &user.Email, &user.Password)
	if err != nil {
		c.JSON(http.StatusUnauthorized, APIResponse{
			Success: false,
			Message: "Invalid credentials",
		})
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password))
	if err != nil {
		c.JSON(http.StatusUnauthorized, APIResponse{
			Success: false,
			Message: "Invalid credentials",
		})
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims{
		UserID: user.ID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	})

	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Message: "Failed to generate token",
		})
		return
	}

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Message: "Login successful",
		Data: gin.H{
			"token": tokenString,
			"user": gin.H{
				"id":    user.ID,
				"name":  user.Name,
				"email": user.Email,
			},
		},
	})
}

func getUserProfile(c *gin.Context) {
	userID := c.GetInt("user_id")

	var user User
	err := db.QueryRow("SELECT id, name, email FROM users WHERE id = ?", userID).
		Scan(&user.ID, &user.Name, &user.Email)
	if err != nil {
		c.JSON(http.StatusNotFound, APIResponse{
			Success: false,
			Message: "User not found",
		})
		return
	}

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Message: "Profile retrieved successfully",
		Data:    user,
	})
}

func updateUserProfile(c *gin.Context) {
	userID := c.GetInt("user_id")

	var req struct {
		Name string `json:"name" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Message: err.Error(),
		})
		return
	}

	_, err := db.Exec("UPDATE users SET name = ? WHERE id = ?", req.Name, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Message: "Failed to update profile",
		})
		return
	}

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Message: "Profile updated successfully",
	})
}

func listQuotes(c *gin.Context) {
	userID := c.GetInt("user_id")

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "10"))
	search := c.Query("search")
	sortBy := c.DefaultQuery("sort_by", "created_at")
	sortOrder := c.DefaultQuery("sort_order", "desc")
	canVote := c.Query("can_vote")

	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 10
	}

	var conditions []string
	var args []interface{}

	if search != "" {
		conditions = append(conditions, "q.quote LIKE ?")
		args = append(args, "%"+search+"%")
	}

	if canVote == "true" {
		conditions = append(conditions, "q.vote_count = 0")
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	validSortFields := map[string]bool{
		"created_at": true,
		"updated_at": true,
		"vote_count": true,
		"quote":      true,
	}
	if !validSortFields[sortBy] {
		sortBy = "created_at"
	}
	if sortOrder != "asc" && sortOrder != "desc" {
		sortOrder = "desc"
	}

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM quotes q %s", whereClause)
	var totalCount int
	err := db.QueryRow(countQuery, args...).Scan(&totalCount)
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Message: "Failed to count quotes",
		})
		return
	}

	offset := (page - 1) * pageSize
	query := fmt.Sprintf(`
		SELECT q.id, q.quote, q.author_id, u.name, q.vote_count, q.created_at, q.updated_at,
		       CASE WHEN v.user_id IS NOT NULL THEN 1 ELSE 0 END as user_voted
		FROM quotes q
		LEFT JOIN users u ON q.author_id = u.id
		LEFT JOIN votes v ON q.id = v.quote_id AND v.user_id = ?
		%s
		ORDER BY q.%s %s
		LIMIT ? OFFSET ?
	`, whereClause, sortBy, sortOrder)

	queryArgs := append([]interface{}{userID}, args...)
	queryArgs = append(queryArgs, pageSize, offset)

	rows, err := db.Query(query, queryArgs...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Message: "Failed to fetch quotes",
		})
		return
	}
	defer rows.Close()

	var quotes []Quote
	for rows.Next() {
		var q Quote
		err := rows.Scan(&q.ID, &q.Quote, &q.AuthorID, &q.AuthorName, &q.VoteCount,
			&q.CreatedAt, &q.UpdatedAt, &q.UserVoted)
		if err != nil {
			continue
		}
		q.CanBeVoted = q.VoteCount == 0
		quotes = append(quotes, q)
	}

	totalPages := (totalCount + pageSize - 1) / pageSize

	response := QuoteListResponse{
		Quotes:     quotes,
		TotalCount: totalCount,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Message: "Quotes retrieved successfully",
		Data:    response,
	})
}

func getQuote(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Message: "Invalid quote ID",
		})
		return
	}

	userID := c.GetInt("user_id")

	var q Quote
	err = db.QueryRow(`
		SELECT q.id, q.quote, q.author_id, u.name, q.vote_count, q.created_at, q.updated_at,
		       CASE WHEN v.user_id IS NOT NULL THEN 1 ELSE 0 END as user_voted
		FROM quotes q
		LEFT JOIN users u ON q.author_id = u.id
		LEFT JOIN votes v ON q.id = v.quote_id AND v.user_id = ?
		WHERE q.id = ?
	`, userID, id).Scan(&q.ID, &q.Quote, &q.AuthorID, &q.AuthorName, &q.VoteCount,
		&q.CreatedAt, &q.UpdatedAt, &q.UserVoted)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, APIResponse{
				Success: false,
				Message: "Quote not found",
			})
		} else {
			c.JSON(http.StatusInternalServerError, APIResponse{
				Success: false,
				Message: "Failed to fetch quote",
			})
		}
		return
	}

	q.CanBeVoted = q.VoteCount == 0

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Message: "Quote retrieved successfully",
		Data:    q,
	})
}

func createQuote(c *gin.Context) {
	userID := c.GetInt("user_id")

	var req QuoteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Message: err.Error(),
		})
		return
	}

	result, err := db.Exec("INSERT INTO quotes (quote, author_id) VALUES (?, ?)",
		req.Quote, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Message: "Failed to create quote",
		})
		return
	}

	quoteID, _ := result.LastInsertId()

	c.JSON(http.StatusCreated, APIResponse{
		Success: true,
		Message: "Quote created successfully",
		Data: gin.H{
			"id":    quoteID,
			"quote": req.Quote,
		},
	})
}

func updateQuote(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Message: "Invalid quote ID",
		})
		return
	}

	userID := c.GetInt("user_id")

	var req QuoteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Message: err.Error(),
		})
		return
	}

	var authorID, voteCount int
	err = db.QueryRow("SELECT author_id, vote_count FROM quotes WHERE id = ?", id).
		Scan(&authorID, &voteCount)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, APIResponse{
				Success: false,
				Message: "Quote not found",
			})
		} else {
			c.JSON(http.StatusInternalServerError, APIResponse{
				Success: false,
				Message: "Database error",
			})
		}
		return
	}

	if authorID != userID {
		c.JSON(http.StatusForbidden, APIResponse{
			Success: false,
			Message: "You can only edit your own quotes",
		})
		return
	}

	if voteCount > 0 {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Message: "Cannot edit quote that has been voted on",
		})
		return
	}

	_, err = db.Exec("UPDATE quotes SET quote = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
		req.Quote, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Message: "Failed to update quote",
		})
		return
	}

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Message: "Quote updated successfully",
	})
}

func deleteQuote(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Message: "Invalid quote ID",
		})
		return
	}

	userID := c.GetInt("user_id")

	var authorID, voteCount int
	err = db.QueryRow("SELECT author_id, vote_count FROM quotes WHERE id = ?", id).
		Scan(&authorID, &voteCount)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, APIResponse{
				Success: false,
				Message: "Quote not found",
			})
		} else {
			c.JSON(http.StatusInternalServerError, APIResponse{
				Success: false,
				Message: "Database error",
			})
		}
		return
	}

	if authorID != userID {
		c.JSON(http.StatusForbidden, APIResponse{
			Success: false,
			Message: "You can only delete your own quotes",
		})
		return
	}

	if voteCount > 0 {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Message: "Cannot delete quote that has been voted on",
		})
		return
	}

	_, err = db.Exec("DELETE FROM quotes WHERE id = ?", id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Message: "Failed to delete quote",
		})
		return
	}

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Message: "Quote deleted successfully",
	})
}

func voteHandler(c *gin.Context) {
	userID := c.GetInt("user_id")

	var req VoteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Message: err.Error(),
		})
		return
	}

	if req.Action != "vote" && req.Action != "unvote" {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Message: "Action must be 'vote' or 'unvote'",
		})
		return
	}

	var voteCount int
	err := db.QueryRow("SELECT vote_count FROM quotes WHERE id = ?", req.QuoteID).
		Scan(&voteCount)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, APIResponse{
				Success: false,
				Message: "Quote not found",
			})
		} else {
			c.JSON(http.StatusInternalServerError, APIResponse{
				Success: false,
				Message: "Database error",
			})
		}
		return
	}

	var existingVoteID int
	err = db.QueryRow("SELECT id FROM votes WHERE user_id = ? AND quote_id = ?",
		userID, req.QuoteID).Scan(&existingVoteID)
	hasVoted := err == nil

	if req.Action == "vote" {
		if hasVoted {
			c.JSON(http.StatusBadRequest, APIResponse{
				Success: false,
				Message: "You have already voted on this quote",
			})
			return
		}

		if voteCount > 0 {
			c.JSON(http.StatusBadRequest, APIResponse{
				Success: false,
				Message: "Cannot vote on quote that already has votes",
			})
			return
		}

		tx, err := db.Begin()
		if err != nil {
			c.JSON(http.StatusInternalServerError, APIResponse{
				Success: false,
				Message: "Failed to start transaction",
			})
			return
		}
		defer tx.Rollback()

		userAgent := c.GetHeader("User-Agent")
		ipAddress := c.ClientIP()

		_, err = tx.Exec("INSERT INTO votes (user_id, quote_id, user_agent, ip_address) VALUES (?, ?, ?, ?)",
			userID, req.QuoteID, userAgent, ipAddress)
		if err != nil {
			c.JSON(http.StatusInternalServerError, APIResponse{
				Success: false,
				Message: "Failed to record vote",
			})
			return
		}

		_, err = tx.Exec("UPDATE quotes SET vote_count = vote_count + 1 WHERE id = ?", req.QuoteID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, APIResponse{
				Success: false,
				Message: "Failed to update vote count",
			})
			return
		}

		err = tx.Commit()
		if err != nil {
			c.JSON(http.StatusInternalServerError, APIResponse{
				Success: false,
				Message: "Failed to commit vote",
			})
			return
		}

		c.JSON(http.StatusOK, APIResponse{
			Success: true,
			Message: "Vote recorded successfully",
			Data: gin.H{
				"quote_id": req.QuoteID,
				"user_id":  userID,
				"action":   "vote",
			},
		})

	} else {
		if !hasVoted {
			c.JSON(http.StatusBadRequest, APIResponse{
				Success: false,
				Message: "You haven't voted on this quote",
			})
			return
		}

		tx, err := db.Begin()
		if err != nil {
			c.JSON(http.StatusInternalServerError, APIResponse{
				Success: false,
				Message: "Failed to start transaction",
			})
			return
		}
		defer tx.Rollback()

		_, err = tx.Exec("DELETE FROM votes WHERE user_id = ? AND quote_id = ?",
			userID, req.QuoteID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, APIResponse{
				Success: false,
				Message: "Failed to remove vote",
			})
			return
		}

		_, err = tx.Exec("UPDATE quotes SET vote_count = vote_count - 1 WHERE id = ?", req.QuoteID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, APIResponse{
				Success: false,
				Message: "Failed to update vote count",
			})
			return
		}

		err = tx.Commit()
		if err != nil {
			c.JSON(http.StatusInternalServerError, APIResponse{
				Success: false,
				Message: "Failed to commit unvote",
			})
			return
		}

		c.JSON(http.StatusOK, APIResponse{
			Success: true,
			Message: "Vote removed successfully",
			Data: gin.H{
				"quote_id": req.QuoteID,
				"user_id":  userID,
				"action":   "unvote",
			},
		})
	}
}

func getMyVotes(c *gin.Context) {
	userID := c.GetInt("user_id")

	rows, err := db.Query(`
		SELECT v.id, v.user_id, v.quote_id, v.user_agent, v.ip_address, v.created_at,
		       q.quote, q.vote_count
		FROM votes v
		JOIN quotes q ON v.quote_id = q.id
		WHERE v.user_id = ?
		ORDER BY v.created_at DESC
	`, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Message: "Database error",
		})
		return
	}
	defer rows.Close()

	var votes []gin.H
	for rows.Next() {
		var vote Vote
		var quote Quote
		err := rows.Scan(&vote.ID, &vote.UserID, &vote.QuoteID, &vote.UserAgent,
			&vote.IPAddress, &vote.CreatedAt, &quote.Quote, &quote.VoteCount)
		if err != nil {
			continue
		}

		votes = append(votes, gin.H{
			"vote": vote,
			"quote": gin.H{
				"id":         vote.QuoteID,
				"quote":      quote.Quote,
				"vote_count": quote.VoteCount,
			},
		})
	}

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Message: "Votes retrieved successfully",
		Data: gin.H{
			"votes": votes,
			"count": len(votes),
		},
	})
}
