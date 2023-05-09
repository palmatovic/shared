package conf

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/antihax/optional"
	"github.com/elastic/go-elasticsearch/v8"
	"github.com/go-playground/validator/v10"
	"github.com/go-sql-driver/mysql"
	"github.com/palmatovic/shared/util"
	sql "gorm.io/driver/mysql"
	"gorm.io/gorm"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type serviceConfiguration struct {
	app   *app   `json:"app" validate:"required"`
	infra *infra `json:"infra" validate:"required"`
}

type app struct {
	port    *int    `json:"port" validate:"omitempty,gt=0"`
	name    *string `json:"name" validate:"omitempty,min=5"`
	baseurl *string `json:"url" validate:"omitempty,url"`
}

type infra struct {
	database *client  `json:"database" validate:"omitempty"`
	elastic  *client `json:"elastic" validate:"omitempty"`
}


func (c client) getElasticClient() (*elasticsearch.Client, error) {

	var cfg elasticsearch.Config
	pwd, err := c.getPassword()
	if err!=nil {return nil, err}
	cfg = elasticsearch.Config{
		Username:  c.username,
		Password:  pwd,
		Addresses: []string{
			func() string{
				a := fmt.Sprintf("https://%s:%d",c.host,c.port)
				if c.useSSL{
					a = strings.ReplaceAll(a,"http","https")
				}
				return a
			}(),
		},
		Transport: &http.Transport{
			MaxIdleConnsPerHost:   10,
			ResponseHeaderTimeout: time.Second,
			DialContext:           (&net.Dialer{Timeout: time.Second}).DialContext,
		},
	}
	if c.useSSL {
		certificate, err := c.getSSLCertificate()
		if err != nil {
			return nil, err
		}
		cfg.CACert = certificate
		cfg.Transport = &http.Transport{
			MaxIdleConnsPerHost:   10,
			ResponseHeaderTimeout: time.Second,
			DialContext:           (&net.Dialer{Timeout: time.Second}).DialContext,
			TLSClientConfig: &tls.Config{
				MinVersion:         tls.VersionTLS12,
				InsecureSkipVerify: c.InsecureSkipVerify,
			},
		}
	}
	if elasticClient, err = elasticsearch.NewClient(cfg); err != nil {
		return nil, err
	}
	if _, err = elasticClient.Info(); err != nil {
		return nil, err
	}

	return elasticClient, nil

}

type client struct {
	host                          string `json:"host" validate:"omitempty,min=5"`
	port                          int    `json:"port" validate:"omitempty,min=5"`
	username                      string `json:"username" validate:"omitempty,min=5"`
	passwordFilepath              string `json:"password_filepath" validate:"omitempty,min=5"`
	sslCertificateFilepath        string `json:"ssl_certificate_filepath" validate:"omitempty,required_if=UseSSL true"`
	useSSL                        bool   `json:"use_ssl" validate:"required"`
	debug                         bool   `json:"debug" validate:"required"`
	automigrate                   bool   `json:"automigrate" validate:"required"`
	databaseName                  string `json:"database_name" validate:"omitempty"`
	useEncryptedPassword          bool   `json:"use_encrypted_password" validate:"required"`
	passwordEncryptionKeyFilepath string `json:"password_encryption_key_filepath" validate:"required_if=UseEncryptedPassword true"`
	skipSslVerification            bool  `json:"skipSslVerification" validate:"required_if=UseEncryptedPassword true"`
}

func (c client) getDatabaseClient(dbTables []interface{}) (db *gorm.DB, err error) {
	var typeTLS string
	if c.useSSL {
		typeTLS = "custom"
	} else {
		typeTLS = optional.EmptyString().Value()
	}
	pwd, err := c.getPassword()
	if err != nil {
		return nil, err
	}
	configDB := mysql.Config{
		User:                 c.username,
		Passwd:               pwd,
		Addr:                 c.GetAddress(),
		Net:                  "tcp",
		DBName:               c.databaseName,
		Loc:                  time.UTC,
		ParseTime:            true,
		AllowNativePasswords: true,
		TLSConfig:            typeTLS,
	}

	connectionString := configDB.FormatDSN()

	if c.useSSL {
		sslCert, err := c.getSSLCertificate()
		if err != nil {
			return nil, err
		}
		err = mysql.RegisterTLSConfig(typeTLS, &tls.Config{
			RootCAs:    sslCert,
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

	if c.debug {
		db = db.Debug()
	}

	if c.automigrate {
		err = db.AutoMigrate(db, dbTables)
		if err != nil {
			return nil, err
		}
	}

	return db, nil
}

func (c client) getPassword() (string, error) {
	if c.useEncryptedPassword {
		pwdEncryptBytes, err := os.ReadFile(c.passwordEncryptionKeyFilepath)
		if err != nil {
			return "", err
		}
		return util.ReadEncryptedPasswordFromFile(c.passwordFilepath, pwdEncryptBytes)
	}
	pwdBytes, err := os.ReadFile(c.passwordFilepath)
	if err != nil {
		return "", err
	}
	return string(pwdBytes), nil
}

func (c client) getSSLCertificate() (*x509.CertPool, error) {
	fileCA := c.sslCertificateFilepath
	rootCertPool := x509.NewCertPool()
	CA, err := os.ReadFile(fileCA)
	if err != nil {
		return nil, fmt.Errorf("cannot read ca-certfile")
	}
	if validCA := rootCertPool.AppendCertsFromPEM(CA); !validCA {
		return nil, fmt.Errorf("failed to append ca from ca-cert")
	}
	return rootCertPool, nil
}

func (c client) GetDatabaseAddress() string {
	return fmt.Sprintf("%s:%c", c.host, c.port)
}

type ConfigSetup struct {
	Database struct {
		Tables []interface{}
	}
}

type Module struct {
	Database *gorm.DB
}

func LoadServiceConfiguration(configFilePath string, setup ConfigSetup) (*Module, error) {
	file, err := os.Open(configFilePath)
	if err != nil {
		return nil, fmt.Errorf("unable to open file %s: %w", configFilePath, err)
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)
	// Verify that the file is a JSON file
	if info, err := file.Stat(); err == nil && !info.IsDir() {
		if ext := filepath.Ext(info.Name()); ext != ".json" {
			return nil, fmt.Errorf("the file %s is not a JSON file", configFilePath)
		}
	} else {
		return nil, fmt.Errorf("unable to read file information for %s: %w", configFilePath, err)
	}
	// Parse the JSON file into a ServiceConfiguration struct
	decoder := json.NewDecoder(file)
	config := new(serviceConfiguration)

	if err = decoder.Decode(config); err != nil {
		return nil, fmt.Errorf("unable to parse file %s: %w", configFilePath, err)
	}
	// Validate the ServiceConfiguration struct
	validate := validator.New()
	if err := validate.Struct(config); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	// if exist database
	module := Module{}

	if config.infra.database != nil {
		db, err := config.infra.database.getDatabaseClient(setup.Database.Tables)
		if err != nil {
			return nil, err
		}
		module.Database = db
	}

	if config.infra.elastic != nil {
		db, err := config.infra.database.(setup.Database.Tables)
		if err != nil {
			return nil, err
		}
		module.Database = db
	}

	return module, nil
}
