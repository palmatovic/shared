package database

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/antihax/optional"
	"github.com/go-sql-driver/mysql"
	"os"
	"time"

	sql "gorm.io/driver/mysql"
	"gorm.io/gorm"
	"shared/conf"
)

// GetDB open new connection pool.
// This method has to be invoked only once, maybe you have to make some tuning for pool size
func GetDB(databaseConfig *conf.Database, dbTables ...interface{}) (db *gorm.DB, err error) {
	var typeTLS string
	if databaseConfig.UseSSL {
		typeTLS = "custom"
	} else {
		typeTLS = optional.EmptyString().Value()
	}
	configDB := mysql.Config{
		User:                 databaseConfig.Username,
		Passwd:               databaseConfig.GetPassword(),
		Addr:                 databaseConfig.GetAddress(),
		Net:                  "tcp",
		DBName:               databaseConfig.DatabaseName,
		Loc:                  time.UTC,
		ParseTime:            true,
		AllowNativePasswords: true,
		TLSConfig:            typeTLS,
	}

	connectionString := configDB.FormatDSN()

	if databaseConfig.UseSSL {
		fileCA := databaseConfig.SSLCertificateFilepath
		rootCertPool := x509.NewCertPool()
		CA, err := os.ReadFile(fileCA)
		if err != nil {
			return nil, fmt.Errorf("cannot read ca-certfile")
		}
		if validCA := rootCertPool.AppendCertsFromPEM(CA); !validCA {
			return nil, fmt.Errorf("failed to append ca from ca-cert")
		}
		err = mysql.RegisterTLSConfig(typeTLS, &tls.Config{
			RootCAs:    rootCertPool,
			MinVersion: tls.VersionTLS12,
		})
		if err != nil {
			return nil, err
		}
	}
	db, err = gorm.Open(sql.Open(connectionString), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	if databaseConfig.Debug {
		db = db.Debug()
	}

	if databaseConfig.Automigrate {
		err = db.AutoMigrate(db, dbTables)
		if err != nil {
			return nil, err
		}
	}

	return db, nil
}

//type Format int64

//const (
//	LeftJoin Format = iota
//	TableColumn
//)
//
//func (df Format) Format(params ...string) string {
//	switch df {
//	case LeftJoin:
//		return fmt.Sprintf("LEFT JOIN %s ON %s.%s=%s.%s ", params[0], params[0], params[1], params[2], params[3])
//	case TableColumn:
//		return strings.Join([]string{params[0], ".", params[1]}, optional.EmptyString().Value())
//	}
//	return optional.EmptyString().Value()
//}
