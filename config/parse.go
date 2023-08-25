package config

import (
	"fmt"
	"gopkg.in/yaml.v2"
	"os"
)

func Load() (Config, error) {
	file, err := os.Open("config.yml")
	if err != nil {
		return Config{}, fmt.Errorf("can't open file: %w", err)
	}

	var c Config
	if err = yaml.NewDecoder(file).Decode(&c); err != nil {
		return Config{}, fmt.Errorf("can't parse yaml: %w", err)
	}

	return c, nil
}
