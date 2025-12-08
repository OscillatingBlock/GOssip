package models

import (
	"github.com/google/uuid"
	"time"
)

type OneTimePreKey struct {
	ID     int64     `bun:",pk,autoincrement"`
	UserID uuid.UUID `bun:",notnull,type:uuid"`
	User   *User     `bun:"rel:belongs-to,join:user_id=id"`

	KeyID      uint32    `bun:",notnull"`
	PublicKey  []byte    `bun:",notnull"` // 32 bytes Curve25519
	Used       bool      `bun:",default:false"`
	UploadedAt time.Time `bun:",default:current_timestamp"`
}
