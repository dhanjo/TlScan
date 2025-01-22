package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"time"
)

type Vulnerability struct {
	Finding  string `json:"finding"`
	Severity string `json:"severity"`
	ID       string `json:"id"`
}

type CertificateExpiry struct {
	Status     string `json:"status"`
	ExpiryDate string `json:"expiry_date"`
	StartDate  string `json:"start_date"`
}

type ScanResult struct {
	Target            string            `json:"target"`
	IP                string            `json:"ip"`
	Port              string            `json:"port"`
	Grade             string            `json:"grade"`
	Vulnerabilities   []Vulnerability   `json:"vulnerabilities"`
	CertificateExpiry CertificateExpiry `json:"certificate_expiry"`
	Error             string            `json:"error,omitempty"`
}

func cleanANSI(input string) string {
	re := regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)
	return re.ReplaceAllString(input, "")
}

func runTestSSL(target string) (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("failed to get current directory: %v", err)
	}
	testSSLPath := filepath.Join(cwd, "testssl", "testssl.sh")
	outputDir := filepath.Join(cwd, "output")
	if _, err := os.Stat(outputDir); os.IsNotExist(err) {
		if err := os.Mkdir(outputDir, 0755); err != nil {
			return "", fmt.Errorf("failed to create output directory: %v", err)
		}
	}
	timestamp := time.Now().Format("20060102-1504")
	outputFile := fmt.Sprintf("%s_p443-%s.json", target, timestamp)
	outputFilePath := filepath.Join(outputDir, outputFile)

	cmd := exec.Command(testSSLPath, "--jsonfile", outputFilePath, target)
	cmdOutput, err := cmd.CombinedOutput() // Capture stdout and stderr
	if err != nil {
		fmt.Printf("Warning: testssl.sh exited with error: %v, output: %s\n", err, string(cmdOutput))
	}

	return outputFilePath, nil
}

func parseTestSSL(data []map[string]interface{}) (ScanResult, error) {
	var result ScanResult
	var vulnerabilities []Vulnerability

	for _, entry := range data {
		id, _ := entry["id"].(string)
		finding, _ := entry["finding"].(string)
		severity, _ := entry["severity"].(string)

		if id == "service" {
			ipPort := entry["ip"].(string)
			if parts := regexp.MustCompile(`^(.*)/(.*)$`).FindStringSubmatch(ipPort); len(parts) == 3 {
				result.Target = parts[1]
				result.IP = parts[2]
			}
			result.Port = entry["port"].(string)
		} else if id == "overall_grade" {
			result.Grade = finding
		} else if id == "cert_expirationStatus" {
			result.CertificateExpiry.Status = finding
		} else if id == "cert_notBefore" {
			result.CertificateExpiry.StartDate = finding
		} else if id == "cert_notAfter" {
			result.CertificateExpiry.ExpiryDate = finding
		} else {
			vulnerabilities = append(vulnerabilities, Vulnerability{
				ID:       id,
				Finding:  finding,
				Severity: severity,
			})
		}
	}

	result.Vulnerabilities = vulnerabilities
	return result, nil
}

func readTestSSLFile(filePath string) ([]map[string]interface{}, error) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %v", err)
	}

	var parsedData []map[string]interface{}
	err = json.Unmarshal(data, &parsedData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %v", err)
	}

	return parsedData, nil
}

func apiHandler(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	if target == "" {
		http.Error(w, `{"error":"Target parameter is missing"}`, http.StatusBadRequest)
		return
	}

	result := ScanResult{}

	outputFilePath, err := runTestSSL(target)
	if err != nil {
		result.Error = fmt.Sprintf("TestSSL error: %v", err)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
		return
	}

	rawData, err := readTestSSLFile(outputFilePath)
	if err != nil {
		result.Error = fmt.Sprintf("Failed to read TestSSL output: %v", err)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
		return
	}

	result, err = parseTestSSL(rawData)
	if err != nil {
		result.Error = fmt.Sprintf("Failed to extract data: %v", err)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func main() {
	http.HandleFunc("/scan", apiHandler)
	fmt.Println("Starting server on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		fmt.Printf("Error starting server: %v\n", err)
	}
}
