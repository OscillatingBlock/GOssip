package models

import (
	"github.com/google/uuid"
	"time"
)

type SignedPreKey struct {
	UserID uuid.UUID `bun:",pk,type:uuid"`
	User   *User     `bun:"rel:belongs-to,join:user_id=id"`

	KeyID     uint32 `bun:",notnull"` // client-chosen, e.g. incremental
	PublicKey []byte `bun:",notnull"` // 32 bytes Curve25519
	Signature []byte `bun:",notnull"` // 64 bytes — signed by IdentityKey.SigningPrivateKey

	UploadedAt time.Time `bun:",default:current_timestamp"`
}
