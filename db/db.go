package db

import (
    "context"
    "os"
	"fmt"

    "github.com/jackc/pgx/v4"
)

func Connect() (*pgx.Conn, error) {
    connStr := os.Getenv("DATABASE_URL")
    if connStr == "" {
        return nil, fmt.Errorf("DATABASE_URL environment variable is not set")
    }

    conn, err := pgx.Connect(context.Background(), connStr)
    if err != nil {
        return nil, err
    }

    err = conn.Ping(context.Background())
    if err != nil {
        return nil, err
    }

    return conn, nil
}