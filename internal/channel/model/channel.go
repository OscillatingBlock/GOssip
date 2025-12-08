package model

import (
	"github.com/google/uuid"
	user "gossip/internal/user/model"
	"time"
)

type Channel struct {
	ID uuid.UUID `bun:",pk,type:uuid,default:gen_random_uuid()"`

	// Basic info
	Name      string `bun:",notnull"`
	Topic     string `bun:",null"`
	IsPrivate bool   `bun:",default:false"` // invite-only vs public
	IsDM      bool   `bun:",default:false"` // future: auto-DM channels

	// Ownership & metadata
	CreatorID uuid.UUID  `bun:",notnull,type:uuid"`
	Creator   *user.User `bun:"rel:belongs-to,join:creator_id=id"`

	CreatedAt time.Time  `bun:",nullzero,notnull,default:current_timestamp"`
	UpdatedAt time.Time  `bun:",nullzero,notnull,default:current_timestamp"`
	DeletedAt *time.Time `bun:",soft_delete"` // soft delete support

	// Activity tracking
	LastMessageAt *time.Time `bun:",nullzero"`
	MessageCount  int64      `bun:",default:0"`
}
