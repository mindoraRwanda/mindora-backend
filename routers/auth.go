package routers

import (
    "net/http"

    "github.com/gin-gonic/gin"
    "github.com/jackc/pgx/v4"
    "golang.org/x/crypto/bcrypt"
    "your_module/models"
)

func SetupAuthRoutes(r *gin.Engine, conn *pgx.Conn) {
    r.POST("/api/auth/register", registerHandler(conn))
    r.POST("/api/auth/login", loginHandler(conn))
}

func registerHandler(conn *pgx.Conn) gin.HandlerFunc {
    return func(c *gin.Context) {
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
    }
}

func loginHandler(conn *pgx.Conn) gin.HandlerFunc {
    return func(c *gin.Context) {
        // Implementation of login handler
    }
}