package main

import (
	"archive/zip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"log"
	mathrand "math/rand"
	"os"
	"path/filepath"

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

func dumpPasswordsToZip(db *sql.DB, filename string) error {
	// create zip file
	zipFile, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create a zip file, %v", err)
	}
	defer zipFile.Close() // to close file in the end

	// zipWriter init
	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	// create csv file inside zip
	csvFile, err := zipWriter.Create("passwords.csv")
	if err != nil {
		return fmt.Errorf("failed to create passwords.csv file, %v", err)
	}

	// csvWriter init
	csvWriter := csv.NewWriter(csvFile)
	defer csvWriter.Flush()

	// write CSV Header
	if err := csvWriter.Write([]string{"app_name", "username", "password", "created_at"}); err != nil {
		return fmt.Errorf("failed to write csv header, %v", err)
	}

	// fetch data from db
	rows, err := db.Query("SELECT app_name, username, password, created_at FROM passwords")
	if err != nil {
		return fmt.Errorf("failed to fetch data from Database, %v", err)
	}
	defer rows.Close()

	for rows.Next() {
		var appName, userName, password, createdAt string
		if err := rows.Scan(&appName, &userName, &password, &createdAt); err != nil {
			return fmt.Errorf("failed to assign data from row, %v", err)
		}

		if err := csvWriter.Write([]string{appName, userName, password, createdAt}); err != nil {
			return fmt.Errorf("failed to write data to csv, %v", err)
		}

	}
	return nil
}

func restorePasswordsFromZip(db *sql.DB, filename string) error {
	// open zip file
	reader, err := zip.OpenReader(filename)
	if err != nil {
		return fmt.Errorf("failed to read zip file, %v", err)
	}
	defer reader.Close()

	var csvFile *zip.File
	for _, file := range reader.File {
		if filepath.Ext(file.Name) == ".csv" {
			csvFile = file
			break
		}
	}
	if csvFile == nil {
		return fmt.Errorf("no .csv file found in zip")
	}
	// open csv file
	fileReader, err := csvFile.Open()
	if err != nil {
		return fmt.Errorf("failed to open csv file, %v", err)
	}
	defer fileReader.Close()

	// csv reader
	csvReader := csv.NewReader(fileReader)

	// skipping header row
	if _, err := csvReader.Read(); err != nil {
		return fmt.Errorf("failed to read csv header, %v", err)
	}

	// create empty passwords table, if not exists
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS passwords2 (
			app_name TEXT NOT NULL,
			username TEXT NOT NULL,
			password TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create table, %v", err)
	}

	// write row data into db
	for {
		record, err := csvReader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read csv record, %v", err)
		}

		// write into db
		_, dbErr := db.Exec("INSERT INTO passwords2 (app_name, username, password, created_at) VALUES ($1, $2, $3, $4)", record[0], record[1], record[2], record[3])
		if dbErr != nil {
			return fmt.Errorf("failed to insert record into database, %v", dbErr)
		}
	}

	return nil
}

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

	var dumpDb = &cobra.Command{
		Use:   "dump [filename]",
		Short: "Dump Database into zip",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			err := dumpPasswordsToZip(db, args[0])
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("Dumped DB to %v:\n", args[0])
		},
	}

	var restoreDb = &cobra.Command{
		Use:   "restore [filename]",
		Short: "Restore Database from zip",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			err := restorePasswordsFromZip(db, args[0])
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("Restored DB from %v:\n", args[0])
		},
	}

	rootCmd.AddCommand(generateCmd, getCmd, updateCmd, deleteCmd, dumpDb, restoreDb)

	connectDB(db)
	defer db.Close()

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func connectDB(db *sql.DB) {
	err := db.Ping()
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
