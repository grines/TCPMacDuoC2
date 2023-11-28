package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"runtime"
	"sort"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

const (
	darwinUserDataDir  = "Library/Application Support/Google/Chrome"
	linuxUserDataDir   = ".config/google-chrome"
	windowsUserDataDir = `Google\Chrome\User Data`
)

func getUserDataDir() string {
	var userDataDir string
	var home string
	var ok bool

	switch runtime.GOOS {
	case "windows":
		home, ok = os.LookupEnv("LOCALAPPDATA")
		if !ok {
			log.Fatal("LOCALAPPDATA environment variable not found")
		}
		userDataDir = fmt.Sprintf("%s\\%s", home, windowsUserDataDir)
	case "linux":
		home, ok = os.LookupEnv("HOME")
		if !ok {
			log.Fatal("HOME environment variable not found")
		}
		userDataDir = fmt.Sprintf("%s/%s", home, linuxUserDataDir)
	case "darwin":
		home, ok = os.LookupEnv("HOME")
		if !ok {
			log.Fatal("HOME environment variable not found")
		}
		userDataDir = fmt.Sprintf("%s/%s", home, darwinUserDataDir)
	}
	return userDataDir
}

func main() {
	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create a new allocator context for the Chrome instance
	dir := getUserDataDir()
	opts := append(chromedp.DefaultExecAllocatorOptions[:], chromedp.UserDataDir(dir), chromedp.Headless)
	allocCtx, cancel := chromedp.NewExecAllocator(ctx, opts...)
	defer cancel()

	// Create a new browser context
	taskCtx, cancel := chromedp.NewContext(allocCtx, chromedp.WithLogf(log.Printf))
	defer cancel()

	// List of URLs to visit
	urls := []string{
		"https://mail.google.com",
		"https://dashboard.stripe.com",
		// Add more URLs as needed
	}

	// Run task to navigate to each URL and then dump cookies
	for _, url := range urls {
		err := chromedp.Run(taskCtx,
			chromedp.Navigate(url),
			dumpCookies(),
		)
		if err != nil {
			log.Fatalf("Failed at %s: %v", url, err)
		}
	}
}

func dumpCookies() chromedp.ActionFunc {
	return func(ctx context.Context) error {
		cookies, err := network.GetCookies().Do(ctx)
		if err != nil {
			return err
		}

		sort.Slice(cookies, func(i, j int) bool {
			return cookies[i].Domain < cookies[j].Domain
		})

		jsonData, err := json.MarshalIndent(cookies, "", "    ")
		if err != nil {
			return err
		}

		fmt.Printf("Cookies: %s\n", jsonData)
		return nil
	}
}
