package main

import (
	"fmt"
	"net/smtp"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// sendAlert sends a real-time alert via email.
// Adjust the SMTP configuration below to match your email server settings.
func sendAlert(message string) {
	// --- SMTP Configuration (adjust these values) ---
	smtpServer := "smtp.gmail.com:587"// SMTP server address and port.
	senderEmail := "arnavgupta372002@gmail.com"     // Sender email address.
	senderPassword := "twea fswt jyec lyzx"       // Sender email password.
	recipientEmail := "arinsahu0@gmail.com"   // Recipient email address.
	// --------------------------------------------------

	// Compose the email subject and body.
	subject := "Subject: [ALERT] Potential Attacker Detected\n"
	body := fmt.Sprintf("A potential attacker has been flagged at %s:\n\n%s", time.Now().Format("2006-01-02 15:04:05"), message)
	msg := []byte(subject + "\n" + body)

	// Set up authentication information.
	auth := smtp.PlainAuth("", senderEmail, senderPassword, strings.Split(smtpServer, ":")[0])

	// Send the email.
	err := smtp.SendMail(smtpServer, auth, senderEmail, []string{recipientEmail}, msg)
	if err != nil {
		logrus.Errorf("Failed to send alert email: %v", err)
	} else {
		logrus.Infof("Alert email sent to %s", recipientEmail)
	}
}
