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
)

// AES-BlockSize is 16 by-default

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
		var app_name, userName, password, createdAt string
		if err := rows.Scan(&app_name, &userName, &password, &createdAt); err != nil {
			return fmt.Errorf("failed to assign data from row, %v", err)
		}

		if err := csvWriter.Write([]string{app_name, userName, password, createdAt}); err != nil {
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
		CREATE TABLE IF NOT EXISTS passwords (
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
		_, dbErr := db.Exec("INSERT INTO passwords (app_name, username, password, created_at) VALUES ($1, $2, $3, $4)", record[0], record[1], record[2], record[3])
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
	// ciphertext length should be same as blocksize
	if len(ciphertext) < aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return string(ciphertext), nil
}

func connectDB(db *sql.DB) {
	err := db.Ping()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Successfully connected to the database")
}

func generatePassword() string {
	// For simplicity, i am generating a basic password
	length := 10
	const characterLength = 6
	const numberLength = 2
	const symbolLength = 2

	const numbers = "1234567890"
	const symbols = "!@#$%^&*_+~-"
	const characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

	result := make([]byte, length)

	// 0 to 6
	for i := 0; i < characterLength; i++ {
		result[i] = characters[mathrand.Intn(len(characters))]
	}
	// 6 to 8
	for i := characterLength; i < characterLength+numberLength; i++ {
		result[i] = numbers[mathrand.Intn(len(numbers))]
	}
	// 8 to 10
	for i := characterLength + numberLength; i < length; i++ {
		result[i] = symbols[mathrand.Intn(len(symbols))]
	}

	// shuffle the pack
	for i := 0; i < length; i++ {
		j := mathrand.Intn(10)
		result[i], result[j] = result[j], result[i]
	}
	return string(result)
}
func storePassword(app_name, username, password string) error {
	// check if app_name, username exists
	encryptedPassword, err := encryptPassword(password)
	if err != nil {
		fmt.Println(err)
		return fmt.Errorf("error encrypting password: %v", err)
	}
	_, err = db.Exec("INSERT INTO passwords (app_name, username, password) VALUES ($1, $2, $3)",
		app_name, username, encryptedPassword)
	if err != nil {
		return fmt.Errorf("error storing password: %v", err)
	}

	return nil
}

func getPasswordByApp(app_name string) ([]encryptedPassword, error) {

	var passwordSlice []encryptedPassword

	rows, err := db.Query("SELECT app_name, username, password, created_at FROM passwords WHERE app_name = $1 AND EXISTS (SELECT 1 FROM passwords WHERE app_name = $1 ORDER BY created_at DESC LIMIT 1)", app_name) // .Scan(&encryptedPassword)
	if err != nil {
		return nil, fmt.Errorf("error while query passwords: %v", err)
	}
	defer rows.Close()

	for rows.Next() {
		var password encryptedPassword
		err := rows.Scan(&password.app_name, &password.username, &password.password, &password.created_at)
		if err != nil {
			return nil, fmt.Errorf("error while reading row %v", err)
		}
		pass := password.password
		decryptedPass, _ := decryptPassword(pass)
		password.password = decryptedPass
		passwordSlice = append(passwordSlice, password)
	}

	return passwordSlice, nil
}

func getPasswordByUsername(username string) ([]encryptedPassword, error) {
	var passwordSlice []encryptedPassword
	fmt.Printf("username %v", username)
	rows, err := db.Query("SELECT app_name, username, password, created_at FROM passwords WHERE username = $1 AND EXISTS (SELECT 1 FROM passwords WHERE username = $1 ORDER BY created_at DESC LIMIT 1)", username) // .Scan(&encryptedPassword)
	if err != nil {
		return nil, fmt.Errorf("error while query passwords: %v", err)
	}
	defer rows.Close()

	for rows.Next() {
		var password encryptedPassword
		err := rows.Scan(&password.app_name, &password.username, &password.password, &password.created_at)
		if err != nil {
			return nil, fmt.Errorf("error while reading row %v", err)
		}
		pass := password.password
		decryptedPass, _ := decryptPassword(pass)
		password.password = decryptedPass
		passwordSlice = append(passwordSlice, password)
	}

	return passwordSlice, nil
}

func deletePassword(app_name string) (string, error) {
	err := db.QueryRow("DELETE password FROM passwords WHERE app_name = $1", app_name)
	if err != nil {
		log.Fatalf("error retrieving password: %v", err)
		return "", fmt.Errorf("error decrypting password: %v", err)
	}
	return "", nil
}

func updatePassword(app_name string, password string) (string, error) {
	encryptedPassword, err := encryptPassword(password)
	if err != nil {
		err := fmt.Sprintf("error encrypting password: %v", err)
		return "", fmt.Errorf("error encrypting password: %v", err)
	}
	fmt.Println(app_name, encryptedPassword)
	updateErr := db.QueryRow("UPDATE passwords SET password=$1 WHERE app_name=$2", encryptedPassword, app_name)
	if updateErr != nil {
		updateErrString := fmt.Sprintf("error updating password: %v", err)
		return "", fmt.Errorf(updateErrString)
	}
	return "", nil

}

func checkIfEntryExists(app_name string, username string) (bool, error) {
	var exists bool
	query := `SELECT EXISTS (SELECT 1 FROM passwords WHERE app_name=$1 AND username=$2 )`
	err := db.QueryRow(query, app_name, username).Scan(&exists)
	if err != nil {
		fmt.Println(err)
		return false, fmt.Errorf("error while checking if username or app_name exists")
	}
	return exists, nil
}
