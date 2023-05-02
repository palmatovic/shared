package conf

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/go-playground/validator/v10"
	"github.com/palmatovic/shared/util"
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
}

type Database struct {
	Host                          string `json:"host" validate:"omitempty,min=5"`
	Port                          int    `json:"port" validate:"omitempty,min=5"`
	Username                      string `json:"username" validate:"omitempty,min=5"`
	PasswordFilepath              string `json:"password_filepath" validate:"omitempty,min=5"`
	SSLCertificateFilepath        string `json:"ssl_certificate_filepath" validate:"omitempty,required_if=UseSSL true"`
	UseSSL                        bool   `json:"use_ssl" validate:"required"`
	Debug                         bool   `json:"debug" validate:"required"`
	Automigrate                   bool   `json:"automigrate" validate:"required"`
	DatabaseName                  string `json:"database_name" validate:"omitempty"`
	UseEncryptedPassword          bool   `json:"use_encrypted_password" validate:"required"`
	PasswordEncryptionKeyFilepath string `json:"password_encryption_key_filepath" validate:"required_if=UseEncryptedPassword true"`
}

//
//func (Database) GetClient() *gorm.DB {
//
//}
//
//func (d Database) GetAddress() string {
//
//}

func (d Database) GetPassword() (string, error) {
	if d.UseEncryptedPassword {
		pwdEncryptBytes, err := os.ReadFile(d.PasswordEncryptionKeyFilepath)
		if err != nil {
			return "", err
		}
		return util.ReadEncryptedPasswordFromFile(d.PasswordFilepath, pwdEncryptBytes)
	}
	pwdBytes, err := os.ReadFile(d.PasswordFilepath)
	if err != nil {
		return "", err
	}
	return string(pwdBytes), nil

}

func (d Database) GetSSLCertificate() (*x509.CertPool, error) {
	fileCA := d.SSLCertificateFilepath
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

func (d Database) GetAddress() string {
	return fmt.Sprintf("%s:%d", d.Host, d.Port)
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
