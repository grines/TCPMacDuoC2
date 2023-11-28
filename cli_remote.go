package main

import (
	"bufio"
	"encoding/base64"
	"flag"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/chzyer/readline"
	encryption "github.com/grines/minic2/common"
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
	PSK           = "thisiscoolthisiscool1234"
)

type Client struct {
	conn net.Conn
}

func NewClient(address string) (*Client, error) {
	conn, err := net.Dial("tcp", address)
	if err != nil {
		return nil, err
	}

	return &Client{conn: conn}, nil
}

func (c *Client) Close() {
	c.conn.Close()
}

func (c *Client) Reconnect() error {
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

func (c *Client) SendCommand(command string) (string, error) {
	encryptedCommand, err := encryption.Encrypt(command, PSK)
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

	decryptedOutput, err := encryption.Decrypt(string(decodedOutput), PSK)
	if err != nil {
		return "", err
	}

	return decryptedOutput, nil
}

func main() {
	flag.Parse()

	serverAddress := serverIP + ":" + serverPort

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

		updatePromp(rl, client)
		fmt.Println(response)
	}
}

func updatePromp(rl *readline.Instance, client *Client) {
	if rl == nil {
		return // Safeguard against nil readline instance
	}

	currentClientDir, err := client.SendCommand("pwd\n")
	currentClient, err := client.SendCommand("current\n")
	if currentClient == "-1" {
		currentClient = "None"
	}
	if currentClientDir == "No implant selected" {
		currentClientDir = ""
	}
	if err != nil {
		rl.SetPrompt("Implant > ")
	} else {
		rl.SetPrompt(fmt.Sprintf("Implant %s - %s> ", currentClient, currentClientDir))
	}
}
