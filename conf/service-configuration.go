package conf

import (
	"encoding/json"
	"fmt"
	"github.com/elastic/go-elasticsearch/v8"
	"github.com/go-playground/validator/v10"
	"os"
	"path/filepath"
)

type ServiceConfiguration struct {
	App   *App   `json:"app" validate:"required"`
	Infra *Infra `json:"infra" validate:"required"`
}

type App struct {
	Port    *int    `json:"port" validate:"omitempty,gt=0"`
	Name    *string `json:"name" validate:"omitempty,min=5"`
	BaseUrl *string `json:"url" validate:"omitempty,url"`
}

type Infra struct {
	Database *Database `json:"database" validate:"omitempty"`
	Elastic  *Elastic  `json:"elastic" validate:"omitempty"`
}

type Elastic struct {
	Host           string `json:"host" validate:"required,url"`
	Port           int    `json:"port" validate:"required,gt=0"`
	Username       string `json:"username" validate:"omitempty,min=5"`
	Password       string `json:"password" validate:"omitempty,min=5"`
	SSLCertificate string `json:"ssl_certificate" validate:"omitempty,required_if=UseSSL true"`
	UseSSL         string `json:"use_ssl" validate:"omitempty,min=5"`
	Client         elasticsearch.Client
}

type Database struct {
	Host                   string `json:"host" validate:"omitempty,min=5"`
	Port                   int    `json:"port" validate:"omitempty,min=5"`
	Username               string `json:"username" validate:"omitempty,min=5"`
	PasswordFilepath       string `json:"password_filepath" validate:"omitempty,min=5"`
	SSLCertificateFilepath string `json:"ssl_certificate_filepath" validate:"omitempty,required_if=UseSSL true"`
	UseSSL                 bool   `json:"use_ssl" validate:"required"`
	Debug                  bool   `json:"debug" validate:"required"`
	Automigrate            bool   `json:"automigrate" validate:"required"`
	DatabaseName           string `json:"database_name" validate:"omitempty"`

	password       string
	sslCertificate string
	address        string
}

//
//func (Database) GetClient() *gorm.DB {
//
//}
//
//func (d Database) GetAddress() string {
//
//}

func (d Database) GetPassword() string {
	return d.password
}

func (d Database) GetSSLCertificate() string {
	return d.sslCertificate
}

func (d Database) GetAddress() string {
	return d.address
}

func LoadServiceConfiguration(configFilePath string) (*ServiceConfiguration, error) {
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
	config := new(ServiceConfiguration)

	if err = decoder.Decode(config); err != nil {
		return nil, fmt.Errorf("unable to parse file %s: %w", configFilePath, err)
	}
	// Validate the ServiceConfiguration struct
	validate := validator.New()
	if err := validate.Struct(config); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}
	return config, nil
}
