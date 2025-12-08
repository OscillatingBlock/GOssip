package models

import (
	"github.com/google/uuid"
	"time"
)

type IdentityKey struct {
	UserID uuid.UUID `bun:",pk,type:uuid"`
	User   *User     `bun:"rel:belongs-to,join:user_id=id"`

	// Ed25519 — used to sign login challenges and signed prekeys
	SigningPublicKey []byte `bun:",notnull"` // 32 bytes

	// Curve25519 — static key for X3DH (converted from Ed25519)
	EncryptionPublicKey []byte `bun:",notnull"` // 32 bytes

	// When this key was registered (for key rotation later)
	RegisteredAt time.Time `bun:",default:current_timestamp"`
}
