package models

type AdminStaff struct {
    FullName     string `json:"fullname"`
    Email        string `json:"email"`
    PhoneNumber  string `json:"phonenumber"`
    Username     string `json:"username"`
    Password     string `json:"password"`
}