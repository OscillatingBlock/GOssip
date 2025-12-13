package user

import (
	"github.com/google/uuid"
)

// NOTE: commands travel from handler to usecase
// Note: DTO travels from usecase to handler
// Input commands
type RegisterCommand struct {
	Username            string
	DisplayName         string
	IdentityKeyPublic   []byte // Ed25519 signing + Curve25519 encryption public
	EncryptionPublicKey []byte // usually same as converted Ed25519 → X25519
	SignedPreKey        SignedPreKeyUpload
	OneTimePreKeys      []OneTimePreKeyUpload
}

type SignedPreKeyUpload struct {
	KeyID     uint32
	PublicKey []byte
	Signature []byte // signed by identity Ed25519 private key
}

type OneTimePreKeyUpload struct {
	KeyID     uint32
	PublicKey []byte
}

type UploadPreKeysCommand struct {
	SignedPreKey   *SignedPreKeyUpload
	OneTimePreKeys []OneTimePreKeyUpload // can be empty
}

type CompleteLoginCommand struct {
	ChallengeID uuid.UUID
	Signature   []byte // Ed25519 signature of challenge string
}

// Output DTOs
type UserDTO struct {
	ID          uuid.UUID
	Username    string
	DisplayName string
}

type UserProfileDTO struct {
	ID          uuid.UUID
	Username    string
	DisplayName string
	// Add avatar hash, status, etc. later
}

type PreKeyBundleDTO struct {
	UserID                uuid.UUID
	IdentityKey           []byte // Curve25519
	SignedPreKeyID        uint32
	SignedPreKey          []byte
	SignedPreKeySignature []byte
	OneTimePreKeyID       *uint32
	OneTimePreKey         []byte
}

type LoginResponse struct {
	AccessToken string   `json:"access_token"`
	ExpiresIn   int      `json:"expires_in"`
	TokenType   string   `json:"token_type"`
	User        *UserDTO `json:"user"`
}
