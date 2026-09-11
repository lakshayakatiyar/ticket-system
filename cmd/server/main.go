package main

import (
	"embed"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/lakshayakatiyar/eva-bharat-ticket-system/internal/app"
)

//go:embed web/index.html
var webFiles embed.FS

func main() {
	page, err := webFiles.ReadFile("web/index.html")
	if err != nil {
		log.Fatal(err)
	}

	port := strings.TrimSpace(os.Getenv("PORT"))
	if port == "" {
		port = "8080"
	}

	addr := ":" + port
	fmt.Printf("Ticket system is running on %s\n", addr)
	log.Fatal(http.ListenAndServe(addr, app.New(string(page))))
}
