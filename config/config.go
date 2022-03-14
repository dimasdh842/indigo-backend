package config2

import (
	"os"
)

func SetEnv() {
	os.Setenv("SECRET_KEY", "inisecretkeysaya")
}
