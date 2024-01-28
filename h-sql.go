package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

// PayloadHeader represents the combination of payload and header
type PayloadHeader struct {
	Payload string
	Header  string
}

var (
	payloadsPath string
	headersPath  string
	urlsPath     string
	url          string
	mode         string
	outputPath   string
	verbose      bool
	threads      int
)

func init() {
	flag.StringVar(&payloadsPath, "p", "", "Path to the payload file")
	flag.StringVar(&headersPath, "H", "", "Path to the headers file")
	flag.StringVar(&urlsPath, "l", "", "Path to the URLs file")
	flag.StringVar(&url, "u", "", "Single URL")
	flag.StringVar(&mode, "m", "", "Mode: 'single' for a single URL, 'list' for a list of URLs")
	flag.StringVar(&outputPath, "o", "", "Path to the output file")
	flag.BoolVar(&verbose, "v", false, "Run in verbose mode")
	flag.IntVar(&threads, "t", 1, "Number of concurrent threads")
	flag.Parse()
}

// checkVulnerability checks if a URL with a specific header is vulnerable
func checkVulnerability(url string, payloads []string, headers []string, outputFile *os.File, wg *sync.WaitGroup) {
	defer wg.Done()

	client := &http.Client{
		Timeout: 60 * time.Second,
	}

	for _, header := range headers {
		for _, payload := range payloads {
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				log.Fatal(err)
			}

			req.Header.Set(header, payload)

			start := time.Now()
			res, err := client.Do(req)
			elapsed := time.Since(start).Seconds()

			if err != nil {
				log.Printf("The request was not successful due to: %v\n", err)
				return
			}

			defer res.Body.Close()

			result := fmt.Sprintf("Testing for URL: %s\nTesting for Header: %s\nPayload: %s\nResponse Time: %v\n",
				url, header, payload, elapsed)

			if elapsed >= 25 && elapsed <= 50 {
				result += "Status: Vulnerable\n\n"
				fmt.Print(result)

				if outputFile != nil {
					outputFile.WriteString(result)
				}
			} else {
				result += "Status: Not Vulnerable\n\n"
				fmt.Print(result)
			}
		}
	}
}

func main() {
	if payloadsPath == "" || headersPath == "" {
		fmt.Println("Error: Payloads file and Headers file paths are required.")
		return
	}

	payloads := readLines(payloadsPath)
	headers := readLines(headersPath)

	if outputPath != "" {
		outputFile, err := os.Create(outputPath)
		if err != nil {
			log.Fatal(err)
		}
		defer outputFile.Close()

		urls := readLines(urlsPath)

		var wg sync.WaitGroup
		for _, url := range urls {
			wg.Add(1)
			go checkVulnerability(url, payloads, headers, outputFile, &wg)
		}

		wg.Wait()
	} else {
		urls := readLines(urlsPath)
		var wg sync.WaitGroup
		for _, url := range urls {
			wg.Add(1)
			go checkVulnerability(url, payloads, headers, nil, &wg)
		}

		wg.Wait()
	}
}

func readLines(filePath string) []string {
	lines := []string{}

	file, err := os.Open(filePath)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		lines = append(lines, line)
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	return lines
}
