// Package config handles loading and saving application configuration.
package config

import (
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

// Config holds all user-configurable settings.
type Config struct {
	Backend      string `toml:"backend"`       // "python", "go", or "both"
	Theme        string `toml:"theme"`         // "dark", "light", "hacker"
	PythonBin    string `toml:"python_bin"`    // path to python3 interpreter
	PythonScript string `toml:"python_script"` // path to py/main.py
}

// Load reads the config file; returns defaults if it doesn't exist.
func Load() (*Config, error) {
	cfg := &Config{
		Backend:      DefaultBackend,
		Theme:        DefaultTheme,
		PythonBin:    "python3",
		PythonScript: PythonScript,
	}

	path, err := configPath()
	if err != nil {
		return cfg, nil // non-fatal
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return cfg, nil // use defaults
	}

	if _, err := toml.DecodeFile(path, cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// Save persists the current config to disk.
func (c *Config) Save() error {
	path, err := configPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return toml.NewEncoder(f).Encode(c)
}

func configPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ConfigDir, ConfigFile), nil
}
