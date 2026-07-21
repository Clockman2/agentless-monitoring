package auth

import (
	"strings"
	"testing"
)

var testPasswordParams = passwordParams{
	memory:  8 * 1024,
	time:    1,
	threads: 1,
	saltLen: 16,
	keyLen:  32,
}

func TestPasswordHashRoundTrip(t *testing.T) {
	password := "correct horse battery staple"
	encoded, err := hashPassword(password, testPasswordParams)
	if err != nil {
		t.Fatalf("hashPassword() error = %v", err)
	}
	if strings.Contains(encoded, password) {
		t.Fatal("password hash contains the plaintext password")
	}

	valid, err := verifyPassword(password, encoded)
	if err != nil {
		t.Fatalf("verifyPassword() error = %v", err)
	}
	if !valid {
		t.Fatal("correct password did not verify")
	}
	valid, err = verifyPassword("incorrect password", encoded)
	if err != nil {
		t.Fatalf("verify wrong password: %v", err)
	}
	if valid {
		t.Fatal("incorrect password verified")
	}
}

func TestVerifyPasswordRejectsUnsafeParameters(t *testing.T) {
	tests := []string{
		"$argon2id$v=19$m=999999,t=1,p=1$c2FsdHNhbHQ$a2V5a2V5a2V5a2V5a2V5aw",
		"$argon2id$v=19suffix$m=8192,t=1,p=1$c2FsdHNhbHQ$a2V5a2V5a2V5a2V5a2V5aw",
		"$argon2id$v=19$m=8192,t=1,p=1suffix$c2FsdHNhbHQ$a2V5a2V5a2V5a2V5a2V5aw",
	}
	for _, encoded := range tests {
		if valid, err := verifyPassword("password", encoded); err == nil || valid {
			t.Errorf("verifyPassword(%q) = %v, %v; want rejected", encoded, valid, err)
		}
	}
}
