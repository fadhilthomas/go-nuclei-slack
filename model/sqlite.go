package model

import (
	"database/sql"
	"errors"
	"github.com/fadhilthomas/go-nuclei-slack/config"
	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/zerolog/log"
	"os"
)

var(
	dbFile = config.GetStr(config.DATABASE_LOCATION)
)

func InitDB() (database *sql.DB) {
	if _, err := os.Stat(dbFile); err == nil {
		err = os.Remove(dbFile)
		if err != nil {
			log.Error().Str("file", "sqlite").Msg(err.Error())
		}
		log.Debug().Str("file", "sqlite").Msg("remove database")
	} else if os.IsNotExist(err) {
		log.Error().Str("file", "sqlite").Msg(err.Error())
	} else {
		log.Error().Str("file", "sqlite").Msg(err.Error())
	}

	log.Debug().Str("file", "sqlite").Msg("creating database")
	file, err := os.Create(dbFile)
	if err != nil {
		log.Error().Str("file", "sqlite").Msg(err.Error())
		return nil
	}
	log.Info().Str("file", "sqlite").Msg("success to create database")
	_ = file.Close()

	sqlDatabase, err := sql.Open("sqlite3", dbFile)
	if err != nil {
		log.Error().Str("file", "sqlite").Msg(err.Error())
		return nil
	}
	err = createTable(sqlDatabase)
	if err != nil {
		return nil
	}
	if sqlDatabase != nil {
		return sqlDatabase
	}
	return nil
}

func OpenDB() (db *sql.DB) {
	sqlDatabase, err := sql.Open("sqlite3", dbFile)
	if err != nil {
		log.Error().Str("file", "sqlite").Msg(err.Error())
		return nil
	}
	return sqlDatabase
}

func createTable(db *sql.DB) error {
	vulnerabilityTable := `CREATE TABLE "vulnerability" (
		"vulnerability_id"		INTEGER NOT NULL,
		"vulnerability_name"	TEXT NOT NULL,
		"vulnerability_host"	TEXT NOT NULL,
		"vulnerability_status"	TEXT NOT NULL,
		PRIMARY KEY("vulnerability_id" AUTOINCREMENT)
	);`

	err := execSQL(db, "vulnerability", vulnerabilityTable)
	if err != nil {
		return err
	}

	return nil
}

func execSQL(db *sql.DB, tableName string, tableSQL string) error {
	log.Debug().Str("file", "sqlite").Msgf("creating %s table", tableName)
	statement, err := db.Prepare(tableSQL)
	if err != nil {
		log.Error().Str("file", "sqlite").Msg(err.Error())
		return errors.New(err.Error())
	}
	_, err = statement.Exec()
	if err != nil {
		log.Error().Str("file", "sqlite").Msg(err.Error())
		return errors.New(err.Error())
	}
	log.Info().Str("file", "sqlite").Msgf("success to create %s table", tableName)
	return nil
}

func QueryVulnerability(db *sql.DB, vulnerabilityName string, vulnerabilityHost string) (output string, err error) {
	selectSQL := `SELECT vulnerability_status FROM vulnerability WHERE vulnerability_name=$1 AND vulnerability_host=$2;`
	row, err := db.Query(selectSQL, vulnerabilityName, vulnerabilityHost)
	if err != nil {
		log.Error().Str("file", "sqlite").Msg(err.Error())
		return "", errors.New(err.Error())
	}
	defer row.Close()
	for row.Next() {
		if err = row.Scan(&output); err != nil {
			log.Error().Str("file", "sqlite").Msg(err.Error())
			return "", errors.New(err.Error())
		}
	}

	switch {
	case output == "open":
		return "still-open", nil
	case output == "close":
		return "re-open", nil
	default:
		return "new", nil
	}
}

func InsertVulnerability(db *sql.DB, vulnerabilityName string, vulnerabilityHost string, vulnerabilityStatus string) error {
	insertSql := `INSERT INTO vulnerability (vulnerability_name, vulnerability_host, vulnerability_status) VALUES (?, ?, ?)`
	statement, err := db.Prepare(insertSql)
	if err != nil {
		log.Error().Str("file", "sqlite").Msg(err.Error())
		return errors.New(err.Error())
	}
	_, err = statement.Exec(vulnerabilityName, vulnerabilityHost, vulnerabilityStatus)
	if err != nil {
		log.Error().Str("file", "sqlite").Msg(err.Error())
		return errors.New(err.Error())
	}
	return nil
}

func UpdateVulnerabilityStatus(db *sql.DB, vulnerabilityName string, vulnerabilityHost string, vulnerabilityStatus string) error {
	updateSql := `UPDATE vulnerability SET vulnerability_status = ? WHERE vulnerability_name = ? AND vulnerability_host = ?`
	statement, err := db.Prepare(updateSql)
	if err != nil {
		log.Error().Str("file", "sqlite").Msg(err.Error())
		return errors.New(err.Error())
	}
	_, err = statement.Exec(vulnerabilityStatus, vulnerabilityName, vulnerabilityHost)
	if err != nil {
		log.Error().Str("file", "sqlite").Msg(err.Error())
		return errors.New(err.Error())
	}
	return nil
}

func UpdateVulnerabilityStatusAll(db *sql.DB) error {
	updateSql := `UPDATE vulnerability SET vulnerability_status = 'close' WHERE 1 = 1`
	statement, err := db.Prepare(updateSql)
	if err != nil {
		log.Error().Str("file", "sqlite").Msg(err.Error())
		return errors.New(err.Error())
	}
	_, err = statement.Exec()
	if err != nil {
		log.Error().Str("file", "sqlite").Msg(err.Error())
		return errors.New(err.Error())
	}
	return nil
}