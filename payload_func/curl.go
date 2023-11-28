package syscall

import (
	"fmt"
	"io/ioutil"
	"net/http"
)

// SimpleGet performs a GET request to the specified URL and returns the response body as a string.
func SimpleCurl(url string) (string, error) {
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("Error making GET request", err)
		return "", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response body", err)
		return "", err
	}

	return string(body), nil
}
