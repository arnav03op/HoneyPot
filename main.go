package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// initLogging directs logs to a file "honeypot.log" (or stderr if file logging fails).
func initLogging() {
	file, err := os.OpenFile("honeypot.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err == nil {
		logrus.SetOutput(file)
	} else {
		logrus.Info("Failed to log to file, using default stderr")
	}
}

// flagPotentialAttacker writes a potential attacker's profile to "attackers.txt".
func flagPotentialAttacker(remoteAddr, username, details string) {
	file, err := os.OpenFile("attackers.txt", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		logrus.Errorf("Error opening attackers file: %v", err)
		return
	}
	defer file.Close()

	entry := fmt.Sprintf("Time: %s, IP: %s, Username: %s, Details: %s\n",
		time.Now().Format("2006-01-02 15:04:05"), remoteAddr, username, details)
	_, err = file.WriteString(entry)
	if err != nil {
		logrus.Errorf("Error writing to attackers file: %v", err)
		return
	}
	logrus.Infof("Flagged potential attacker: %s", entry)
	// Optionally, send an alert email here.
	sendAlert(entry)
}

func isSuspiciousCommand(cmd string) bool {
	suspiciousKeywords := []string{"rm", "chmod", "cat", "wget", "curl", "nc", "netcat", "sudo", "su"}
	for _, kw := range suspiciousKeywords {
		if strings.Contains(cmd, kw) {
			return true
		}
	}
	return false
}

func main() {
	initLogging()

	// Initialize MongoDB for attacker profiling.
	if err := InitDatabase(); err != nil {
		logrus.Fatalf("Failed to initialize MongoDB: %v", err)
	}

	// Configure Logrus for structured logging.
	logrus.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})
	logrus.Info("Starting GoHoneypot...")

	//const port = process.env.PORT || 4000

	port := os.Getenv("PORT")
	if port == "" {
		port = "2222" // Fallback for local testing.
	}
	listener, err := net.Listen("tcp4", "0.0.0.0:"+port)
	if err != nil {
		logrus.Fatalf("Error starting listener on port %s: %v", port, err)
	}
	defer listener.Close()
	logrus.Infof("Honeypot listening on port %s", port)

	// Accept incoming connections.
	for {
		conn, err := listener.Accept()
		if err != nil {
			logrus.Errorf("Error accepting connection: %v", err)
			continue
		}
		go handleConnection(conn)
	}
}

// handleConnection continuously captures login attempts.
// After a threshold number of attempts, it flags the attacker and transitions to a fake shell session.
func handleConnection(conn net.Conn) {
	defer conn.Close()
	remoteAddr := conn.RemoteAddr().String()
	logrus.Infof("New connection from %s", remoteAddr)

	// Send an SSH banner to mimic a real SSH server.
	banner := "SSH-2.0-OpenSSH_7.4\r\n"
	_, err := conn.Write([]byte(banner))
	if err != nil {
		logrus.Errorf("Error sending banner to %s: %v", remoteAddr, err)
		return
	}

	reader := bufio.NewReader(conn)
	attemptCount := 0
	threshold := 3 // Adjust threshold as desired.

	// Loop to capture every login attempt.
	for {
		_, err = conn.Write([]byte("login: "))
		if err != nil {
			logrus.Errorf("Error sending login prompt to %s: %v", remoteAddr, err)
			return
		}
		username, err := reader.ReadString('\n')
		if err != nil {
			logrus.Infof("Connection with %s closed during username input.", remoteAddr)
			return
		}
		username = strings.TrimSpace(username)

		_, err = conn.Write([]byte("Password: "))
		if err != nil {
			logrus.Errorf("Error sending password prompt to %s: %v", remoteAddr, err)
			return
		}
		password, err := reader.ReadString('\n')
		if err != nil {
			logrus.Infof("Connection with %s closed during password input.", remoteAddr)
			return
		}
		password = strings.TrimSpace(password)

		logrus.Infof("Login attempt from %s | Username: %s | Password: %s", remoteAddr, username, password)
		attemptCount++

		// Store the login attempt in MongoDB.
		if err := AddLoginAttemptToDB(remoteAddr, username, password); err != nil {
			logrus.Errorf("Error storing login attempt in DB: %v", err)
		}

		if attemptCount >= threshold {
			flagPotentialAttacker(remoteAddr, username, "Exceeded login attempt threshold")
			fakeShell(conn, reader, remoteAddr, username)
			return
		} else {
			_, err = conn.Write([]byte("Login incorrect\r\n"))
			if err != nil {
				logrus.Errorf("Error sending login incorrect message to %s: %v", remoteAddr, err)
				return
			}
		}
	}
}

// fakeShell simulates an interactive shell, logging every command.
// It stores each command in MongoDB and flags the attacker if suspicious commands are detected.
func fakeShell(conn net.Conn, reader *bufio.Reader, remoteAddr, username string) {
	welcomeMsg := fmt.Sprintf("Welcome %s! You now have limited shell access. Type 'exit' to disconnect.\n", username)
	_, err := conn.Write([]byte(welcomeMsg))
	if err != nil {
		logrus.Errorf("Error sending welcome message to %s: %v", remoteAddr, err)
		return
	}

	for {
		_, err := conn.Write([]byte("$ "))
		if err != nil {
			logrus.Errorf("Error sending shell prompt to %s: %v", remoteAddr, err)
			break
		}

		cmd, err := reader.ReadString('\n')
		if err != nil {
			logrus.Infof("Connection closed by %s during shell session.", remoteAddr)
			break
		}
		cmd = strings.TrimSpace(cmd)
		logrus.Infof("Command from %s: %s", remoteAddr, cmd)

		// Store the shell command in MongoDB.
		if err := AddShellCommandToDB(remoteAddr, cmd); err != nil {
			logrus.Errorf("Error storing shell command in DB: %v", err)
		}

		// Check if the command is suspicious.
		if isSuspiciousCommand(cmd) {
			flagPotentialAttacker(remoteAddr, username, fmt.Sprintf("Suspicious command: %s", cmd))
		}

		if cmd == "exit" {
			_, _ = conn.Write([]byte("Bye!\n"))
			logrus.Infof("Session with %s ended", remoteAddr)
			break
		}

		response := fmt.Sprintf("bash: %s: command not found\n", cmd)
		_, err = conn.Write([]byte(response))
		if err != nil {
			logrus.Errorf("Error sending response to %s: %v", remoteAddr, err)
			break
		}
	}

	time.Sleep(1 * time.Second)
}
