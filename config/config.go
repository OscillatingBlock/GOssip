package config

import (
	"errors"
	"log/slog"

	"github.com/spf13/viper"
)

type Config struct {
	Server     Server
	Bun        BunConfig
	JWT        JWT
	LoggerMode LoggerMode
}

type Server struct {
	Port        string
	Environment string
}

type BunConfig struct {
	DSN string
}

type LoggerMode struct {
	Development bool
	Prod        bool
	Level       string
}

type JWT struct {
	Secret    string
	ExpiredIn int
}

func LoadConfig(filename string) (*viper.Viper, error) {
	v := viper.New()

	v.SetConfigName(filename)
	v.SetConfigType("yaml")
	v.AddConfigPath("config")

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			return nil, errors.New("config file not found")
		}
		return nil, err
	}
	return v, nil
}

func ParseConfig(v *viper.Viper) (*Config, error) {
	var c Config
	err := v.Unmarshal(&c)
	if err != nil {
		slog.Error("Unable to unmarshal config", "err", err)
		return nil, err
	}
	return &c, nil
}
