package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// --- Database and Logging Setup ---

var (
	mongoClient       *mongo.Client
	profileCollection *mongo.Collection
)

// LoginAttempt represents a login attempt record.
type LoginAttempt struct {
	Username  string    `bson:"username"`
	Password  string    `bson:"password"`
	Timestamp time.Time `bson:"timestamp"`
}

// ShellCommand represents a shell command record.
type ShellCommand struct {
	Command   string    `bson:"command"`
	Timestamp time.Time `bson:"timestamp"`
}

// Profile stores the behavioral data for an attacker identified by IP.
type Profile struct {
	IP            string         `bson:"ip"`
	SessionStart  time.Time      `bson:"session_start"`
	SessionEnd    time.Time      `bson:"session_end"`
	LoginAttempts []LoginAttempt `bson:"login_attempts"`
	ShellCommands []ShellCommand `bson:"shell_commands"`
	ThreatFlags   []string       `bson:"threat_flags,omitempty"`
}

// InitDatabase connects to MongoDB and initializes the profiles collection.
func InitDatabase() error {
	// Use your MongoDB URI. For local testing, this works:
	uri := "mongodb://localhost:27017"
	clientOptions := options.Client().ApplyURI(uri)
	var err error
	mongoClient, err = mongo.Connect(context.TODO(), clientOptions)
	if err != nil {
		return err
	}
	// Verify connection.
	if err = mongoClient.Ping(context.TODO(), nil); err != nil {
		return err
	}
	// Use the "attacker_profiles" database and the "profiles" collection.
	profileCollection = mongoClient.Database("attacker_profiles").Collection("profiles")
	logrus.Info("Connected to MongoDB successfully.")
	return nil
}

// getOrCreateProfile retrieves or creates a profile for the given IP.
func getOrCreateProfile(ip string) (*Profile, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var profile Profile
	err := profileCollection.FindOne(ctx, bson.M{"ip": ip}).Decode(&profile)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			now := time.Now()
			profile = Profile{
				IP:            ip,
				SessionStart:  now,
				SessionEnd:    now,
				LoginAttempts: []LoginAttempt{},
				ShellCommands: []ShellCommand{},
				ThreatFlags:   []string{},
			}
			_, err := profileCollection.InsertOne(ctx, profile)
			if err != nil {
				return nil, err
			}
			return &profile, nil
		}
		return nil, err
	}
	return &profile, nil
}

// AddLoginAttemptToDB stores a login attempt in MongoDB.
func AddLoginAttemptToDB(ip, username, password string) error {
	profile, err := getOrCreateProfile(ip)
	if err != nil {
		return err
	}
	now := time.Now()
	update := bson.M{
		"$push": bson.M{
			"login_attempts": LoginAttempt{
				Username:  username,
				Password:  password,
				Timestamp: now,
			},
		},
		"$set": bson.M{
			"session_end": now,
		},
	}
	opts := options.Update().SetUpsert(true)
	_, err = profileCollection.UpdateOne(context.TODO(), bson.M{"ip": profile.IP}, update, opts)
	if err != nil {
		return err
	}
	logrus.Infof("Stored login attempt for IP %s (username: %s)", ip, username)
	return nil
}

// AddShellCommandToDB stores a shell command in MongoDB.
func AddShellCommandToDB(ip, command string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	now := time.Now()
	update := bson.M{
		"$push": bson.M{
			"shell_commands": ShellCommand{
				Command:   command,
				Timestamp: now,
			},
		},
		"$set": bson.M{
			"session_end": now,
		},
	}
	opts := options.Update().SetUpsert(true)
	_, err := profileCollection.UpdateOne(ctx, bson.M{"ip": ip}, update, opts)
	if err != nil {
		return err
	}
	logrus.Infof("Stored shell command for IP %s: %s", ip, command)
	return nil
}

// AddThreatFlagToDB stores a threat flag in MongoDB.
func AddThreatFlagToDB(ip, flag string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	update := bson.M{
		"$push": bson.M{
			"threat_flags": flag,
		},
	}
	opts := options.Update().SetUpsert(true)
	_, err := profileCollection.UpdateOne(ctx, bson.M{"ip": ip}, update, opts)
	if err != nil {
		return err
	}
	logrus.Infof("Added threat flag for IP %s: %s", ip, flag)
	return nil
}

// --- Threat Intelligence Functions (example implementations) ---

// CheckIPReputation simulates an IP reputation check.
// In a real implementation, you would call an external API.
func CheckIPReputation(ip string) (bool, error) {
	// For demonstration, consider any IP containing "192.0" as malicious.
	if strings.Contains(ip, "192.0") {
		return true, nil
	}
	return false, nil
}

// IsCommonCredential checks if the username or password is common.
func IsCommonCredential(username, password string) bool {
	commonUsernames := []string{"admin", "root", "user", "test"}
	commonPasswords := []string{"123456", "password", "admin", "root", "12345", "12345678"}
	for _, cu := range commonUsernames {
		if strings.EqualFold(username, cu) {
			return true
		}
	}
	for _, cp := range commonPasswords {
		if strings.EqualFold(password, cp) {
			return true
		}
	}
	return false
}

// sendAlert sends a real-time alert (for example, via email).
// In a real implementation, you would integrate with an email service or messaging API.
func sendAlert(message string) {
	// For demonstration, we'll just log the alert.
	logrus.Infof("Alert sent: %s", message)
}

// --- Honeypot Logic ---

func initLogging() {
	file, err := os.OpenFile("honeypot.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err == nil {
		logrus.SetOutput(file)
	} else {
		logrus.Info("Failed to log to file, using default stderr")
	}
}

func main() {
	initLogging()

	// Initialize MongoDB for attacker profiling.
	if err := InitDatabase(); err != nil {
		logrus.Fatalf("Failed to initialize MongoDB: %v", err)
	}

	// Start a simple HTTP server (like Express) for a health-check endpoint on port 8080.
	// This is optional and for demonstration.
	go func() {
		httpPort := "8080"
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "Hello World!")
		})
		logrus.Infof("HTTP server listening on port %s", httpPort)
		if err := http.ListenAndServe("0.0.0.0:"+httpPort, nil); err != nil {
			logrus.Errorf("HTTP server error: %v", err)
		}
	}()

	// Read the PORT environment variable for the honeypot.
	port := os.Getenv("PORT")
	if port == "" {
		port = "2222" // Fallback for local testing.
	}

	// Bind to all interfaces (0.0.0.0) on the given port.
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

	// Extract host without port.
	rawAddr := conn.RemoteAddr().String()
	host, _, err := net.SplitHostPort(rawAddr)
	if err != nil {
		host = rawAddr
	}
	logrus.Infof("New connection from %s", host)

	// Send an SSH banner to mimic a real SSH server.
	banner := "SSH-2.0-OpenSSH_7.4\r\n"
	_, err = conn.Write([]byte(banner))
	if err != nil {
		logrus.Errorf("Error sending banner to %s: %v", host, err)
		return
	}

	reader := bufio.NewReader(conn)
	attemptCount := 0
	threshold := 3 // Adjust threshold as desired.

	// Loop to capture every login attempt.
	for {
		_, err = conn.Write([]byte("login: "))
		if err != nil {
			logrus.Errorf("Error sending login prompt to %s: %v", host, err)
			return
		}
		username, err := reader.ReadString('\n')
		if err != nil {
			logrus.Infof("Connection with %s closed during username input.", host)
			return
		}
		username = strings.TrimSpace(username)

		_, err = conn.Write([]byte("Password: "))
		if err != nil {
			logrus.Errorf("Error sending password prompt to %s: %v", host, err)
			return
		}
		password, err := reader.ReadString('\n')
		if err != nil {
			logrus.Infof("Connection with %s closed during password input.", host)
			return
		}
		password = strings.TrimSpace(password)

		logrus.Infof("Login attempt from %s | Username: %s | Password: %s", host, username, password)
		attemptCount++

		// Store the login attempt in MongoDB.
		if err := AddLoginAttemptToDB(host, username, password); err != nil {
			logrus.Errorf("Error storing login attempt in DB: %v", err)
		}

		// Threat Intelligence Integration:
		// 1. Check IP reputation.
		if isMalicious, err := CheckIPReputation(host); err == nil && isMalicious {
			flagPotentialAttacker(host, username, "High abuse score detected")
		}
		// 2. Check for common credentials.
		if IsCommonCredential(username, password) {
			flagPotentialAttacker(host, username, "Common/default credentials used")
		}

		if attemptCount >= threshold {
			flagPotentialAttacker(host, username, "Exceeded login attempt threshold")
			fakeShell(conn, reader, host, username)
			return
		} else {
			_, err = conn.Write([]byte("Login incorrect\r\n"))
			if err != nil {
				logrus.Errorf("Error sending login incorrect message to %s: %v", host, err)
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
