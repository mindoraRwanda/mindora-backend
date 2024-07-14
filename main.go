package main

import (
    "log"
    "fmt"
    "context"

    "github.com/gin-gonic/gin"
    "github.com/joho/godotenv"
    "github.com/mindoraRwanda/mindora-backend.git/db"
    "github.com/mindoraRwanda/mindora-backend.git/routers"
)

func main() {
    err := godotenv.Load()
    if err != nil {
        log.Fatalf("Error loading .env file")
    }

    conn, err := db.Connect()
    if err != nil {
        log.Fatalf("Unable to connect to database: %v\n", err)
    }
    defer conn.Close(context.Background())

    fmt.Println("Successfully connected to the database!")
    
    r := gin.Default()

    routers.SetupAuthRoutes(r, conn)
    routers.SetupProtectedRoutes(r)
    routers.SetupAdminRoutes(r, conn)
    routers.SetupTherapistRoutes(r, conn)
    routers.SetupPatientRoutes(r, conn)

    r.GET("/", func(c *gin.Context) {
        c.String(200, "Welcome to mindora API!")
    })        

    r.Run()
}