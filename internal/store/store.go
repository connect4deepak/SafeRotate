// Package store is the secret store the demo apps read their database
// credentials from. The MVP uses a JSON file on a shared volume; Kubernetes
// Secrets and AWS Secrets Manager come later behind the same two methods.
package store

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// Credential is what an app needs to log in.
type Credential struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// File is a credential stored as JSON at Path.
type File struct{ Path string }

func (f File) Read() (Credential, error) {
	var c Credential
	b, err := os.ReadFile(f.Path)
	if err != nil {
		return c, err
	}
	return c, json.Unmarshal(b, &c)
}

// Write replaces the file atomically, so a reader never sees half a file.
func (f File) Write(c Credential) error {
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(f.Path), ".cred-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), f.Path)
}
