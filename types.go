package main

import "time"

type encryptedPassword struct {
	app_name   string
	username   string
	password   string
	created_at time.Time
}
