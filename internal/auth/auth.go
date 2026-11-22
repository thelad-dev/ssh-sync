package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

const (
	ScopeUser   = "user"
	ScopeDevice = "device"

	// MinJWTSecretLen is the minimum accepted secret length in bytes.
	MinJWTSecretLen = 32

	// DeviceTokenTTL is the lifetime of device JWTs (rotation via re-register).
	DeviceTokenTTL = 30 * 24 * time.Hour
)

var (
	errSecretUnset    = errors.New("SSH_SYNC_JWT_SECRET nicht gesetzt und kein persistiertes Secret")
	errSecretTooShort = errors.New("SSH_SYNC_JWT_SECRET zu kurz (mindestens 32 Zeichen)")
	errSecretWeak     = errors.New("SSH_SYNC_JWT_SECRET ist ein bekannter Platzhalter und ungültig")
	errTokenNoExp     = errors.New("Token ohne Ablaufzeit")
	knownWeakSecrets  = map[string]struct{}{
		"change-me-in-production":                            {},
		"bitte-durch-ein-langes-zufaelliges-secret-ersetzen": {},
	}
)

type Claims struct {
	Scope    string `json:"scope"`
	DeviceID string `json:"device_id,omitempty"`
	jwt.RegisteredClaims
}

func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func CheckPassword(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func NewDeviceToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// ValidateJWTSecret rejects empty, short, and known placeholder secrets.
func ValidateJWTSecret(v string) error {
	if v == "" {
		return errSecretUnset
	}
	if len(v) < MinJWTSecretLen {
		return errSecretTooShort
	}
	if _, bad := knownWeakSecrets[v]; bad {
		return errSecretWeak
	}
	return nil
}

// JWTSecret loads a strong secret from the environment or a file under dataDir.
// Weak env values fail hard. If the env is unset, a random secret is written to
// dataDir/jwt.secret (mode 0600) and never printed.
func JWTSecret(dataDir string) ([]byte, error) {
	if v := os.Getenv("SSH_SYNC_JWT_SECRET"); v != "" {
		if err := ValidateJWTSecret(v); err != nil {
			return nil, err
		}
		return []byte(v), nil
	}
	if dataDir == "" {
		return nil, errSecretUnset
	}
	path := filepath.Join(dataDir, "jwt.secret")
	if raw, err := os.ReadFile(path); err == nil {
		secret := strings.TrimSpace(string(raw))
		if err := ValidateJWTSecret(secret); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		return []byte(secret), nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	secret := hex.EncodeToString(buf)
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, []byte(secret+"\n"), 0o600); err != nil {
		return nil, err
	}
	fmt.Fprintf(os.Stderr, "WARNUNG: SSH_SYNC_JWT_SECRET nicht gesetzt - neues Secret nach %s geschrieben (Wert nicht geloggt)\n", path)
	return []byte(secret), nil
}

func IssueUserToken(secret []byte, ttl time.Duration) (string, error) {
	claims := Claims{
		Scope: ScopeUser,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secret)
}

func IssueDeviceToken(secret []byte, deviceID string, ttl time.Duration) (string, error) {
	claims := Claims{
		Scope:    ScopeDevice,
		DeviceID: deviceID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   deviceID,
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secret)
}

func ParseToken(secret []byte, token string) (*Claims, error) {
	parsed, err := jwt.ParseWithClaims(token, &Claims{}, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, errors.New("ungültige Signaturmethode")
		}
		return secret, nil
	}, jwt.WithExpirationRequired())
	if err != nil {
		if errors.Is(err, jwt.ErrTokenRequiredClaimMissing) {
			return nil, errTokenNoExp
		}
		return nil, err
	}
	claims, ok := parsed.Claims.(*Claims)
	if !ok || !parsed.Valid {
		return nil, errors.New("ungültiges Token")
	}
	if claims.ExpiresAt == nil {
		return nil, errTokenNoExp
	}
	return claims, nil
}
