package routers

import (
    "context"
    "net/http"
    "os"
    "time"

    "github.com/gin-gonic/gin"
    "github.com/jackc/pgx/v4"
    "golang.org/x/crypto/bcrypt"
    "github.com/dgrijalva/jwt-go"
)

type Therapist struct {
    FullName     string `json:"fullname"`
    Email        string `json:"email"`
    PhoneNumber  string `json:"phonenumber"`
    Username     string `json:"username"`
    Password     string `json:"password"`
}

func SetupTherapistRoutes(r *gin.Engine, conn *pgx.Conn) {
    therapistGroup := r.Group("/api/auth/therapist")

    therapistGroup.POST("/register", registerTherapistHandler(conn))
    therapistGroup.POST("/login", loginTherapistHandler(conn))
}

func registerTherapistHandler(conn *pgx.Conn) gin.HandlerFunc {
    return func(c *gin.Context) {
        var therapist Therapist
        if err := c.ShouldBindJSON(&therapist); err != nil {
            c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request data"})
            return
        }

        hashedPassword, err := bcrypt.GenerateFromPassword([]byte(therapist.Password), bcrypt.DefaultCost)
        if err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Error hashing password"})
            return
        }

        _, err = conn.Exec(context.Background(), 
            "INSERT INTO Therapists (fullname, email, phonenumber, username, password) VALUES ($1, $2, $3, $4, $5)",
            therapist.FullName, therapist.Email, therapist.PhoneNumber, therapist.Username, hashedPassword)
        if err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Error creating therapist user"})
            return
        }

        c.JSON(http.StatusOK, gin.H{"message": "Therapist registered successfully"})
    }
}

func loginTherapistHandler(conn *pgx.Conn) gin.HandlerFunc {
    return func(c *gin.Context) {
        var loginData struct {
            Username string `json:"username"`
            Password string `json:"password"`
        }
        if err := c.ShouldBindJSON(&loginData); err != nil {
            c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request data"})
            return
        }

        var storedPassword string
        var fullName string
        err := conn.QueryRow(context.Background(), 
            "SELECT password, fullname FROM Therapists WHERE username=$1", loginData.Username).Scan(&storedPassword, &fullName)
        if err != nil {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
            return
        }

        err = bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(loginData.Password))
        if err != nil {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
            return
        }

        token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
            "username": loginData.Username,
            "role": "therapist",
            "exp": time.Now().Add(time.Hour * 72).Unix(),
        })

        jwtSecret := os.Getenv("JWT_SECRET")
        tokenString, err := token.SignedString([]byte(jwtSecret))
        if err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Error generating token"})
            return
        }

        c.JSON(http.StatusOK, gin.H{
            "message": "Login successful",
            "token": tokenString,
            "user": gin.H{
                "username": loginData.Username,
                "fullname": fullName,
            },
        })
    }
}
