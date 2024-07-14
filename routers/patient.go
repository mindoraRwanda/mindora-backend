package routers
import (
    "context"
    "net/http"
    "time"
    "fmt"
    "math/rand"
    "strings"

    "github.com/gin-gonic/gin"
    "github.com/jackc/pgx/v4"
    "golang.org/x/crypto/bcrypt"
    "github.com/dgrijalva/jwt-go"
)

type Patient struct {
    ID           int    `json:"id"`
    MedicalID    string `json:"medical_id"`
    FullName     string `json:"fullname"`
    Email        string `json:"email"`
    PhoneNumber  string `json:"phonenumber"`
    Username     string `json:"username"`
    Password     string `json:"password,omitempty"`
}

func generateMedicalID(fullName string) string {
    // Get the first letter of each word in the full name
    initials := ""
    for _, word := range strings.Fields(fullName) {
        initials += strings.ToUpper(word[:1])
    }

    // Generate a random 4-digit number
    randomNum := rand.Intn(10000)

    // Combine initials and random number
    return fmt.Sprintf("%s-%04d", initials, randomNum)
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

        medicalID := generateMedicalID(patient.FullName)

        err = conn.QueryRow(context.Background(), 
            "INSERT INTO Patients (medical_id, fullname, email, phonenumber, username, password) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
            medicalID, patient.FullName, patient.Email, patient.PhoneNumber, patient.Username, hashedPassword).Scan(&patient.ID)
        if err != nil {
            if strings.Contains(err.Error(), "unique constraint") {
                c.JSON(http.StatusConflict, gin.H{"error": "Email or medical ID already exists"})
            } else {
                c.JSON(http.StatusInternalServerError, gin.H{"error": "Error creating patient user"})
            }
            return
        }

        patient.MedicalID = medicalID
        patient.Password = "" // Don't send password back
        c.JSON(http.StatusOK, gin.H{"message": "Patient registered successfully", "patient": patient})
    }
}

func loginPatientHandler(conn *pgx.Conn) gin.HandlerFunc {
    return func(c *gin.Context) {
        var loginData struct {
            Email    string `json:"email"`
            Password string `json:"password"`
        }
        if err := c.ShouldBindJSON(&loginData); err != nil {
            c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
            return
        }

        var patient Patient
        var storedPassword string
        err := conn.QueryRow(context.Background(), 
            "SELECT id, medical_id, fullname, email, phonenumber, username, password FROM Patients WHERE email=$1", 
            loginData.Email).Scan(&patient.ID, &patient.MedicalID, &patient.FullName, &patient.Email, &patient.PhoneNumber, &patient.Username, &storedPassword)
        if err != nil {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
            return
        }

        err = bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(loginData.Password))
        if err != nil {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
            return
        }

        token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
            "email": patient.Email,
            "role": "patient",
            "exp": time.Now().Add(time.Hour * 72).Unix(),
        })

        tokenString, err := token.SignedString(jwtSecret)
        if err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Error generating token"})
            return
        }

        patient.Password = "" // Don't send password back
        c.JSON(http.StatusOK, gin.H{"token": tokenString, "patient": patient})
    }
}