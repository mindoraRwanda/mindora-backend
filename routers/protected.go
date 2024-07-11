package routers

import (
    "fmt"
    "net/http"

    "github.com/gin-gonic/gin"
    "github.com/dgrijalva/jwt-go"
)

func SetupProtectedRoutes(r *gin.Engine) {
    authorized := r.Group("/")
    authorized.Use(authMiddleware())
    authorized.GET("/protected", func(c *gin.Context) {
        c.JSON(http.StatusOK, gin.H{"message": "Welcome to the protected route!"})
    })
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