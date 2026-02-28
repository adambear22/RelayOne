package jwtutil

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	UserID            string   `json:"uid"`
	Role              string   `json:"role"`
	Permissions       []string `json:"perms"`
	LegacyUserID      string   `json:"user_id,omitempty"`
	LegacyPermissions []string `json:"permissions,omitempty"`
	jwt.RegisteredClaims
}

func NewClaims(userID, role string, perms []string, expiry time.Duration) *Claims {
	now := time.Now().UTC()
	claims := &Claims{
		UserID:      userID,
		Role:        role,
		Permissions: perms,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(expiry)),
			NotBefore: jwt.NewNumericDate(now),
		},
	}
	return claims
}

func GenerateAccessToken(claims *Claims, privateKey *rsa.PrivateKey) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(privateKey)
}

func GenerateRefreshToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func ParseAccessToken(tokenStr string, publicKey *rsa.PublicKey) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}))
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, jwt.ErrTokenSignatureInvalid
	}
	claims.normalize()
	return claims, nil
}

func (c *Claims) normalize() {
	if c.UserID == "" {
		c.UserID = c.LegacyUserID
	}
	if len(c.Permissions) == 0 && len(c.LegacyPermissions) > 0 {
		c.Permissions = c.LegacyPermissions
	}
}
