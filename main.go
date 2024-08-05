package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"strconv"

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

func main() {

	envErr := godotenv.Load("db.env")
	if envErr != nil {
		log.Fatal("Error loading db.env file")
	}
	port, getPortEnvErr := strconv.Atoi(os.Getenv("DB_PORT"))
	if getPortEnvErr != nil {
		log.Fatal("Error while reading PORT from db.env", getPortEnvErr)
	}

	var (
		host     = os.Getenv("DB_HOST")
		user     = os.Getenv("DB_USER")
		password = os.Getenv("DB_PASSWORD")
		dbname   = os.Getenv("DB_NAME")
	)
	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s "+
		"password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbname)
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
			var app_name, username = args[0], args[1]
			exists, err := checkIfEntryExists(app_name, username)
			if err != nil {
				log.Fatal(err)
			}
			if exists {
				fmt.Printf("Password for %s with username %s, already exists in database\n", app_name, username)
				return
			}
			password := generatePassword()
			storePassword(app_name, username, password)
			fmt.Printf("Generated and stored password for %s: %s\n", app_name, password)
		},
	}

	var getCmd = &cobra.Command{
		Use:   "get",
		Short: "Retrieve a password",
		Run: func(cmd *cobra.Command, args []string) {
			appFlag := cmd.Flags().Lookup("app").Value.String()
			userFlag := cmd.Flags().Lookup("user").Value.String()

			if appFlag != "" {
				passwordSlice, err := getPasswordByApp(appFlag)
				if err != nil {
					log.Fatal(err)
				}
				if len(passwordSlice) != 0 {
					for id, pass := range passwordSlice {
						fmt.Printf("%d. App: %v Username: %v Password: %v Created On: %v\n", id+1, pass.app_name, pass.username, pass.password, pass.created_at)
					}
				}
			} else if userFlag != "" {
				// TODO: add a swtich using the same fucntion, but with some changes
				passwordSlice, err := getPasswordByUsername(userFlag)
				if err != nil {
					log.Fatal(err)
				}
				if len(passwordSlice) != 0 {
					for _, pass := range passwordSlice {
						fmt.Printf("App: %v Username: %v Password: %v Created On: %v\n", pass.app_name, pass.username, pass.password, pass.created_at)
					}
				}
			} else {
				fmt.Printf("No app or username flags. Either use app or username flag to get password.\nUsage  -a | --app  to get password by app\n -u | --user to get password by username")
			}
		},
	}
	getCmd.Flags().StringP("app", "a", "", "App name")
	getCmd.Flags().StringP("user", "u", "", "User name")

	var updateCmd = &cobra.Command{
		Use:   "update [app_name] [password]",
		Short: "Update a password",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			var app_name, username = args[0], args[1]
			_, err := updatePassword(app_name, username)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("Updated Password for %s:\n", username)
		},
	}
	var deleteCmd = &cobra.Command{
		Use:   "delete [app_name]",
		Short: "Delete a password",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			var app_name = args[0]
			_, err := deletePassword(app_name)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("Deleted Password for %s:\n", app_name)
		},
	}

	var dumpDb = &cobra.Command{
		Use:   "dump [filename]",
		Short: "Dump Database into zip",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			var filename = args[0]
			err := dumpPasswordsToZip(db, filename)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("Dumped DB to %v:\n", filename)
		},
	}

	var restoreDb = &cobra.Command{
		Use:   "restore [filename]",
		Short: "Restore Database from zip",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			var filename = args[0]
			err := restorePasswordsFromZip(db, filename)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("Restored DB from %v:\n", filename)
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
