package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	mathrand "math/rand"
	"os"

	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"github.com/spf13/cobra"
)

var db *sql.DB

var secretKey = []byte("24-byte-loong-secret-key")

const (
	keySize         = 32 // AES-256
	fixedCipherSize = 64
)

func encryptPassword(password string) (string, error) {
	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return "", err
	}

	// Create a fixed-size plaintext
	plaintext := make([]byte, fixedCipherSize-aes.BlockSize)
	copy(plaintext, []byte(password))

	// Generate a random IV
	ciphertext := make([]byte, fixedCipherSize)
	iv := ciphertext[:aes.BlockSize]
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}

	// Encrypt
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

func decryptPassword(encryptedPassword string) (string, error) {
	ciphertext, err := base64.URLEncoding.DecodeString(encryptedPassword)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return "", err
	}

	if len(ciphertext) < aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return string(ciphertext), nil
}

func main() {

	var rootCmd = &cobra.Command{Use: "varden"}

	var generateCmd = &cobra.Command{
		Use:   "generate [app_name] [username]",
		Short: "Generate and store a new password",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			password := generatePassword()
			storePassword(args[0], args[1], password)
			fmt.Printf("Generated and stored password for %s\n", args[0])
		},
	}

	var getCmd = &cobra.Command{
		Use:   "get [app_name]",
		Short: "Retrieve a password",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			password, err := getPassword(args[0])
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("Password for %s: %s\n", args[0], password)
		},
	}

	var updateCmd = &cobra.Command{
		Use:   "update [app_name] [password]",
		Short: "Update a password",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			_, err := updatePassword(args[0], args[1])
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("Updated Password for %s:\n", args[1])
		},
	}
	var deleteCmd = &cobra.Command{
		Use:   "delete [app_name]",
		Short: "Delete a password",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			_, err := deletePassword(args[0])
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("Deleted Password for %s:\n", args[0])
		},
	}

	rootCmd.AddCommand(generateCmd, getCmd, updateCmd, deleteCmd)

	connectDB()
	defer db.Close()

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func connectDB() {
	envErr := godotenv.Load("db.env")
	if envErr != nil {
		log.Fatal("Error loading .env file")
	}
	var (
		host     = os.Getenv("DB_HOST")
		user     = os.Getenv("DB_USER")
		password = os.Getenv("DB_PASSWORD")
		dbname   = os.Getenv("DB_NAME")
	)
	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s "+
		"password=%s dbname=%s sslmode=disable",
		host, 5432, user, password, dbname)
	var err error
	db, err = sql.Open("postgres", psqlInfo)
	if err != nil {
		log.Fatal(err)
	}

	err = db.Ping()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Successfully connected to the database")
}

func generatePassword() string {
	// For simplicity, we're generating a basic password
	length := 10
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+~.<>|"
	result := make([]byte, length)

	for i := 0; i < length; i++ {
		result[i] = charset[mathrand.Intn(len(charset))]
	}
	return string(result)
}
func storePassword(appName, username, password string) error {
	encryptedPassword, err := encryptPassword(password)
	if err != nil {
		fmt.Println(err)
		return fmt.Errorf("error encrypting password: %v", err)
	}
	_, err = db.Exec("INSERT INTO passwords (app_name, username, password) VALUES ($1, $2, $3)",
		appName, username, encryptedPassword)
	if err != nil {
		return fmt.Errorf("error storing password: %v", err)
	}

	return nil
}

func getPassword(appName string) (string, error) {
	var encryptedPassword string
	err := db.QueryRow("SELECT password FROM passwords WHERE app_name = $1", appName).Scan(&encryptedPassword)
	if err != nil {
		return "", fmt.Errorf("error retrieving password: %v", err)
	}

	password, err := decryptPassword(encryptedPassword)
	if err != nil {
		return "", fmt.Errorf("error decrypting password: %v", err)
	}

	return password, nil
}

func deletePassword(appName string) (string, error) {
	err := db.QueryRow("DELETE password FROM passwords WHERE app_name = $1", appName)
	if err != nil {
		log.Fatalf("error retrieving password: %v", err)
		return "", fmt.Errorf("error decrypting password: %v", err)

	}
	return "", nil
}

func updatePassword(appName string, password string) (string, error) {
	encryptedPassword, err := encryptPassword(password)
	if err != nil {
		err := fmt.Sprintf("error encrypting password: %v", err)
		return "", fmt.Errorf("error encrypting password: %v", err)

	}
	updateErr := db.QueryRow("UPDATE passwords SET password=$1 WHERE app_name=$2", encryptedPassword, appName)
	if updateErr != nil {
		updateErrString := fmt.Sprintf("error updating password: %v", err)
		return "", fmt.Errorf("error updating password: %v", updateErrString)

	}
	return "", nil

}
