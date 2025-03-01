package main

import (
	"context"
	"time"

	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

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
}

// InitDatabase connects to MongoDB and initializes the profiles collection.
func InitDatabase() error {
	// Update this URI as needed for your MongoDB environment.
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

// getOrCreateProfile retrieves the profile document for the given IP, or creates one if it doesn't exist.
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

// AddLoginAttemptToDB stores a login attempt for the given IP in MongoDB.
func AddLoginAttemptToDB(ip, username, password string) error {
	// Retrieve or create a profile explicitly.
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
	// You can use the profile's IP (or an identifier from profile, if stored) here.
	_, err = profileCollection.UpdateOne(context.TODO(), bson.M{"ip": profile.IP}, update, opts)
	if err != nil {
		return err
	}
	logrus.Infof("Stored login attempt for IP %s (username: %s)", ip, username)
	return nil
}

// AddShellCommandToDB stores a shell command for the given IP in MongoDB.
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
