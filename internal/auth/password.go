package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const (
	minimumPasswordRunes = 12
	maximumPasswordBytes = 1024
	maximumHashMemory    = 256 * 1024
	maximumHashTime      = 10
	maximumHashThreads   = 16
)

type passwordParams struct {
	memory  uint32
	time    uint32
	threads uint8
	saltLen uint32
	keyLen  uint32
}

var productionPasswordParams = passwordParams{
	memory:  64 * 1024,
	time:    3,
	threads: 4,
	saltLen: 16,
	keyLen:  32,
}

func validateNewPassword(password string) error {
	if !utf8.ValidString(password) {
		return fmt.Errorf("password must be valid UTF-8")
	}
	if utf8.RuneCountInString(password) < minimumPasswordRunes {
		return fmt.Errorf("password must contain at least %d characters", minimumPasswordRunes)
	}
	if len(password) > maximumPasswordBytes {
		return fmt.Errorf("password must not exceed %d bytes", maximumPasswordBytes)
	}
	return nil
}

func hashPassword(password string, params passwordParams) (string, error) {
	salt := make([]byte, params.saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}

	key := argon2.IDKey(
		[]byte(password),
		salt,
		params.time,
		params.memory,
		params.threads,
		params.keyLen,
	)
	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		params.memory,
		params.time,
		params.threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

func verifyPassword(password, encoded string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, fmt.Errorf("unsupported password hash format")
	}

	version, err := parseUintParameter(parts[2], "v=", 8)
	if err != nil || version != argon2.Version {
		return false, fmt.Errorf("unsupported Argon2 version")
	}

	parameterParts := strings.Split(parts[3], ",")
	if len(parameterParts) != 3 {
		return false, fmt.Errorf("invalid password hash parameters")
	}
	memory, memoryErr := parseUintParameter(parameterParts[0], "m=", 32)
	iterations, timeErr := parseUintParameter(parameterParts[1], "t=", 32)
	threads, threadsErr := parseUintParameter(parameterParts[2], "p=", 8)
	if memoryErr != nil || timeErr != nil || threadsErr != nil {
		return false, fmt.Errorf("invalid password hash parameters")
	}
	params := passwordParams{memory: uint32(memory), time: uint32(iterations), threads: uint8(threads)}
	if params.memory == 0 || params.memory > maximumHashMemory ||
		params.time == 0 || params.time > maximumHashTime ||
		params.threads == 0 || params.threads > maximumHashThreads {
		return false, fmt.Errorf("password hash parameters are outside allowed limits")
	}

	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil || len(salt) < 8 || len(salt) > 64 {
		return false, fmt.Errorf("invalid password hash salt")
	}
	expected, err := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if err != nil || len(expected) < 16 || len(expected) > 64 {
		return false, fmt.Errorf("invalid password hash key")
	}

	actual := argon2.IDKey(
		[]byte(password),
		salt,
		params.time,
		params.memory,
		params.threads,
		uint32(len(expected)),
	)
	return subtle.ConstantTimeCompare(actual, expected) == 1, nil
}

func parseUintParameter(value, prefix string, bits int) (uint64, error) {
	if !strings.HasPrefix(value, prefix) || len(value) == len(prefix) {
		return 0, fmt.Errorf("missing parameter %s", prefix)
	}
	parsed, err := strconv.ParseUint(strings.TrimPrefix(value, prefix), 10, bits)
	if err != nil {
		return 0, fmt.Errorf("parse parameter %s: %w", prefix, err)
	}
	return parsed, nil
}

func burnPasswordAttempt(password string, params passwordParams) {
	staticSalt := []byte("invalid-user-salt")
	_ = argon2.IDKey(
		[]byte(password),
		staticSalt,
		params.time,
		params.memory,
		params.threads,
		params.keyLen,
	)
}
