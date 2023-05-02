package database

import (
	"crypto/tls"
	"github.com/antihax/optional"
	"github.com/go-sql-driver/mysql"
	"github.com/palmatovic/shared/conf"
	"time"

	sql "gorm.io/driver/mysql"
	"gorm.io/gorm"
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
	pwd, err := databaseConfig.GetPassword()
	if err != nil {
		return nil, err
	}
	configDB := mysql.Config{
		User:                 databaseConfig.Username,
		Passwd:               pwd,
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
		err = mysql.RegisterTLSConfig(typeTLS, &tls.Config{
			RootCAs:    databaseConfig.GetSSLCertificate(),
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
