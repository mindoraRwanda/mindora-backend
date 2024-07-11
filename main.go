package main

import (
   "context"
   "log"
   "fmt"
   "net/http"
   "os"
   "time"
   

  "github.com/gin-gonic/gin"
  "github.com/jackc/pgx/v4"
  "github.com/joho/godotenv"
  "golang.org/x/crypto/bcrypt"
   "github.com/dgrijalva/jwt-go"
)

var jwtSecret = []byte("your_secret_key")

type User struct {
    Username string `json:"username"`
    Password string `json:"password"`
}

func main() {
    err := godotenv.Load()
    if err != nil {
        log.Fatalf("Error loading .env file")
    }

    connStr := os.Getenv("DATABASE_URL")
    if connStr == "" {
        log.Fatal("DATABASE_URL environment variable is not set")
    }

    conn, err := pgx.Connect(context.Background(), connStr)
    if err != nil {
        log.Fatalf("Unable to connect to database: %v\n", err)
    }
    defer conn.Close(context.Background())

    err = conn.Ping(context.Background())
    if err != nil {
        log.Fatalf("Unable to ping the database: %v\n", err)
    }

    fmt.Println("Successfully connected to the database!")
    
    r := gin.Default()

    r.POST("/register", func(c *gin.Context) {
        var user User
        if err := c.ShouldBindJSON(&user); err != nil {
            c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
            return
        }

        hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
        if err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Error hashing password"})
            return
        }

        _, err = conn.Exec(context.Background(), "INSERT INTO users (username, password) VALUES ($1, $2)", user.Username, hashedPassword)
        if err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Error creating user"})
            return
        }

        c.JSON(http.StatusOK, gin.H{"message": "User registered successfully"})
    })

    r.POST("/login", func(c *gin.Context) {
        var user User
        if err := c.ShouldBindJSON(&user); err != nil {
            c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
            return
        }

        var storedPassword string
        err := conn.QueryRow(context.Background(), "SELECT password FROM users WHERE username=$1", user.Username).Scan(&storedPassword)
        if err != nil {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
            return
        }

        err = bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(user.Password))
        if err != nil {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
            return
        }

        token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
            "username": user.Username,
            "exp":      time.Now().Add(time.Hour * 72).Unix(),
        })

        tokenString, err := token.SignedString(jwtSecret)
        if err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Error generating token"})
            return
        }

        c.JSON(http.StatusOK, gin.H{"token": tokenString})
    })

    authorized := r.Group("/")
    authorized.Use(authMiddleware())
    authorized.GET("/protected", func(c *gin.Context) {
        c.JSON(http.StatusOK, gin.H{"message": "Welcome to the protected route!"})
    })

    r.GET("/", func(c *gin.Context) {
        c.String(http.StatusOK, "Welcome to my API!")
    })

    r.Run()
}

func authMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        tokenString := c.GetHeader("Authorization")
        if tokenString == "" {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is required"})
            c.Abort()
            return
        }

        token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
            if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
                return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
            }
            return jwtSecret, nil
        })

        if err != nil || !token.Valid {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
            c.Abort()
            return
        }

        c.Next()
    }
}