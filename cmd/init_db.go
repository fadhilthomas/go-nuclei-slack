package main

import "github.com/fadhilthomas/go-nuclei-slack/model"

func main() {
	database := model.InitDB()
	if database == nil {
		return
	}
}
