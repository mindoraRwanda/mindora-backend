package routers

import (
    "context"
    "net/http"
    "time"

    "github.com/gin-gonic/gin"
    "github.com/jackc/pgx/v4"
)

type Appointment struct {
    ID             int       `json:"id"`
    PatientID      int       `json:"patient_id"`
    TherapistID    int       `json:"therapist_id"`
    AppointmentTime time.Time `json:"appointment_time"`
    Status         string    `json:"status"`
}

func SetupAppointmentRoutes(r *gin.Engine, conn *pgx.Conn) {
    appointmentGroup := r.Group("/api/appointments")

    appointmentGroup.POST("/create", createAppointmentHandler(conn))
    appointmentGroup.GET("/:id", getAppointmentHandler(conn))
    appointmentGroup.PUT("/:id", updateAppointmentHandler(conn))
    appointmentGroup.DELETE("/:id", deleteAppointmentHandler(conn))
}

func createAppointmentHandler(conn *pgx.Conn) gin.HandlerFunc {
    return func(c *gin.Context) {
        var appointment Appointment
        if err := c.ShouldBindJSON(&appointment); err != nil {
            c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
            return
        }

        err := conn.QueryRow(context.Background(), 
            "INSERT INTO Appointments (patient_id, therapist_id, appointment_time, status) VALUES ($1, $2, $3, $4) RETURNING id",
            appointment.PatientID, appointment.TherapistID, appointment.AppointmentTime, appointment.Status).Scan(&appointment.ID)
        if err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Error creating appointment"})
            return
        }

        c.JSON(http.StatusOK, gin.H{"message": "Appointment created successfully", "appointment": appointment})
    }
}

func getAppointmentHandler(conn *pgx.Conn) gin.HandlerFunc {
    return func(c *gin.Context) {
        appointmentID := c.Param("id")
        var appointment Appointment
        err := conn.QueryRow(context.Background(), 
            "SELECT id, patient_id, therapist_id, appointment_time, status FROM Appointments WHERE id=$1", appointmentID).Scan(
            &appointment.ID, &appointment.PatientID, &appointment.TherapistID, &appointment.AppointmentTime, &appointment.Status)
        if err != nil {
            c.JSON(http.StatusNotFound, gin.H{"error": "Appointment not found"})
            return
        }
        c.JSON(http.StatusOK, gin.H{"appointment": appointment})
    }
}

func updateAppointmentHandler(conn *pgx.Conn) gin.HandlerFunc {
    return func(c *gin.Context) {
        appointmentID := c.Param("id")
        var appointment Appointment
        if err := c.ShouldBindJSON(&appointment); err != nil {
            c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
            return
        }

        _, err := conn.Exec(context.Background(), 
            "UPDATE Appointments SET patient_id=$1, therapist_id=$2, appointment_time=$3, status=$4 WHERE id=$5",
            appointment.PatientID, appointment.TherapistID, appointment.AppointmentTime, appointment.Status, appointmentID)
        if err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Error updating appointment"})
            return
        }

        c.JSON(http.StatusOK, gin.H{"message": "Appointment updated successfully"})
    }
}

func deleteAppointmentHandler(conn *pgx.Conn) gin.HandlerFunc {
    return func(c *gin.Context) {
        appointmentID := c.Param("id")
        _, err := conn.Exec(context.Background(), "DELETE FROM Appointments WHERE id=$1", appointmentID)
        if err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Error deleting appointment"})
            return
        }
        c.JSON(http.StatusOK, gin.H{"message": "Appointment deleted successfully"})
    }
}
