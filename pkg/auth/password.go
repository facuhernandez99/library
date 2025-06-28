package auth

import (
	"errors"
	"unicode"

	"golang.org/x/crypto/bcrypt"
)

// Password validation errors
var (
	ErrPasswordTooShort  = errors.New("password must be at least 8 characters long")
	ErrPasswordTooLong   = errors.New("password must be less than 100 characters long")
	ErrPasswordNoUpper   = errors.New("password must contain at least one uppercase letter")
	ErrPasswordNoLower   = errors.New("password must contain at least one lowercase letter")
	ErrPasswordNoDigit   = errors.New("password must contain at least one digit")
	ErrPasswordNoSpecial = errors.New("password must contain at least one special character")
	ErrPasswordEmpty     = errors.New("password cannot be empty")
)

// HashPassword generates a bcrypt hash of the password.
func HashPassword(password string) (string, error) {
	if password == "" {
		return "", ErrPasswordEmpty
	}

	// Validate password strength before hashing
	if err := ValidatePasswordStrength(password); err != nil {
		return "", err
	}

	// Generate hash with default cost (currently 10)
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	return string(bytes), nil
}

// CheckPasswordHash compares a password with its hash.
func CheckPasswordHash(password, hash string) bool {
	if password == "" || hash == "" {
		return false
	}

	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// ValidatePasswordStrength checks if password meets security requirements.
func ValidatePasswordStrength(password string) error {
	if len(password) == 0 {
		return ErrPasswordEmpty
	}

	if len(password) < 8 {
		return ErrPasswordTooShort
	}

	if len(password) > 100 {
		return ErrPasswordTooLong
	}

	var (
		hasUpper   bool
		hasLower   bool
		hasDigit   bool
		hasSpecial bool
	)

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsDigit(char):
			hasDigit = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	if !hasUpper {
		return ErrPasswordNoUpper
	}
	if !hasLower {
		return ErrPasswordNoLower
	}
	if !hasDigit {
		return ErrPasswordNoDigit
	}
	if !hasSpecial {
		return ErrPasswordNoSpecial
	}

	return nil
}

// ValidatePasswordBasic provides basic password validation (length only).
// Use this for less strict requirements.
func ValidatePasswordBasic(password string) error {
	if len(password) == 0 {
		return ErrPasswordEmpty
	}

	if len(password) < 8 {
		return ErrPasswordTooShort
	}

	if len(password) > 100 {
		return ErrPasswordTooLong
	}

	return nil
}
