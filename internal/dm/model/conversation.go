package model

import (
	"github.com/google/uuid"
	"time"
)

type DMConversation struct {
	ID            uuid.UUID `bun:",pk,default:gen_random_uuid()"`
	User1ID       string    `bun:",notnull"`
	User2ID       string    `bun:",notnull"`
	CreatedAt     time.Time `bun:",default:current_timestamp"`
	LastMessageAt time.Time `bun:",nullzero"`

	// Unique index in migration:
	// CREATE UNIQUE INDEX idx_dm_pair ON dm_conversations(least(user1_id,user2_id), greatest(user1_id,user2_id));
}

type DMMessage struct {
	ID             string `bun:",pk,default:gen_random_uuid()"`
	ConversationID string `bun:",notnull"`

	SenderID    string `bun:",notnull"` // for filtering/debug
	RecipientID string `bun:",notnull"` // for inbox delivery

	Ciphertext []byte    `bun:",notnull"` // fully encrypted blob (header + payload)
	ReceivedAt time.Time `bun:",default:current_timestamp"`
	ExpiresAt  time.Time `bun:",notnull"` // auto-delete after 30–90 days
}
