package routers

import (
    "context"
    "net/http"
    "time"

    "github.com/gin-gonic/gin"
    "github.com/jackc/pgx/v4"
    "golang.org/x/crypto/bcrypt"
    "github.com/dgrijalva/jwt-go"
)

type Patient struct {
    FullName     string `json:"fullname"`
    Email        string `json:"email"`
    PhoneNumber  string `json:"phonenumber"`
    Username     string `json:"username"`
    Password     string `json:"password"`
}

func SetupPatientRoutes(r *gin.Engine, conn *pgx.Conn) {
    patientGroup := r.Group("/api/auth/patient")

    patientGroup.POST("/register", registerPatientHandler(conn))
    patientGroup.POST("/login", loginPatientHandler(conn))
}

func registerPatientHandler(conn *pgx.Conn) gin.HandlerFunc {
    return func(c *gin.Context) {
        var patient Patient
        if err := c.ShouldBindJSON(&patient); err != nil {
            c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
            return
        }

        hashedPassword, err := bcrypt.GenerateFromPassword([]byte(patient.Password), bcrypt.DefaultCost)
        if err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Error hashing password"})
            return
        }

        _, err = conn.Exec(context.Background(), 
            "INSERT INTO Patients (fullname, email, phonenumber, username, password) VALUES ($1, $2, $3, $4, $5)",
            patient.FullName, patient.Email, patient.PhoneNumber, patient.Username, hashedPassword)
        if err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Error creating patient user"})
            return
        }

        c.JSON(http.StatusOK, gin.H{"message": "Patient registered successfully"})
    }
}

func loginPatientHandler(conn *pgx.Conn) gin.HandlerFunc {
    return func(c *gin.Context) {
        var loginData struct {
            Username string `json:"username"`
            Password string `json:"password"`
        }
        if err := c.ShouldBindJSON(&loginData); err != nil {
            c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
            return
        }

        var storedPassword string
        err := conn.QueryRow(context.Background(), 
            "SELECT password FROM Patients WHERE username=$1", loginData.Username).Scan(&storedPassword)
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
            "role": "patient",
            "exp": time.Now().Add(time.Hour * 72).Unix(),
        })

        tokenString, err := token.SignedString(jwtSecret)
        if err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Error generating token"})
            return
        }

        c.JSON(http.StatusOK, gin.H{"token": tokenString})
    }
}