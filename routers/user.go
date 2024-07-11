package routers

import (
    "net/http"
    "context"

    "github.com/gin-gonic/gin"
    "github.com/jackc/pgx/v4"
    "github.com/mindoraRwanda/mindora-backend.git/models"
)

func SetupUserRoutes(r *gin.Engine, conn *pgx.Conn) {
    userGroup := r.Group("/api/users")
    userGroup.Use(authMiddleware()) // Ensure these routes are protected

    userGroup.GET("/profile", getUserProfile(conn))
    userGroup.PUT("/profile", updateUserProfile(conn))
    userGroup.DELETE("/account", deleteUserAccount(conn))
}

func getUserProfile(conn *pgx.Conn) gin.HandlerFunc {
    return func(c *gin.Context) {
        username := c.GetString("username") // Assuming you set this in the authMiddleware
        
        var user models.User
        err := conn.QueryRow(context.Background(), "SELECT username FROM users WHERE username=$1", username).Scan(&user.Username)
        if err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Error fetching user profile"})
            return
        }

        c.JSON(http.StatusOK, gin.H{"username": user.Username})
    }
}

func updateUserProfile(conn *pgx.Conn) gin.HandlerFunc {
    return func(c *gin.Context) {
        username := c.GetString("username")
        
        var updateData struct {
            NewUsername string `json:"new_username"`
        }

        if err := c.ShouldBindJSON(&updateData); err != nil {
            c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
            return
        }

        _, err := conn.Exec(context.Background(), "UPDATE users SET username=$1 WHERE username=$2", updateData.NewUsername, username)
        if err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Error updating user profile"})
            return
        }

        c.JSON(http.StatusOK, gin.H{"message": "Profile updated successfully"})
    }
}

func deleteUserAccount(conn *pgx.Conn) gin.HandlerFunc {
    return func(c *gin.Context) {
        username := c.GetString("username")

        _, err := conn.Exec(context.Background(), "DELETE FROM users WHERE username=$1", username)
        if err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Error deleting user account"})
            return
        }

        c.JSON(http.StatusOK, gin.H{"message": "Account deleted successfully"})
    }
}