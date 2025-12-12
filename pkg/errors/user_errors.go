package errors

var (
	// Domain errors — used in usecase/repository
	ErrUsernameTaken                = AlreadyExists("username is already taken")
	ErrUserNotFound                 = NotFound("user not found")
	ErrInvalidUsername              = InvalidArg("username must be 3-32 chars, lowercase letters, numbers and underscores only")
	ErrInvalidDisplayName           = InvalidArg("display name cannot be empty")
	ErrIdentityKeyMissing           = FailedPrecondition("identity key not registered")
	ErrSignedPreKeyMissing          = FailedPrecondition("signed prekey not uploaded")
	ErrNoPreKeysAvailable           = FailedPrecondition("no one-time prekeys available")
	ErrInvalidChallenge             = InvalidArg("invalid or expired login challenge")
	ErrInvalidSignature             = Unauthorized("signature verification failed")
	ErrChallengeUsed                = FailedPrecondition("challenge already used")
	ErrInvalidChallengeID           = InvalidArg("invalid challenge id")
	ErrInvalidSignedPreKey          = InvalidArg("invalid signed prekey")
	ErrInvalidOneTimePreKey         = InvalidArg("invalid one-time prekey")
	ErrInvalidSignedPreKeySignature = InvalidArg("invalid signed prekey signature")
)

func ErrPreKeyBundleFailed(cause error) error {
	return Wrap(CodeFailedPrecondition, "failed to fetch prekey bundle", cause)
}

func ErrRegistrationFailed(cause error) error {
	return Wrap(CodeInternal, "registration failed", cause)
}

func ErrLoginFailed(cause error) error {
	return Wrap(CodeUnauthenticated, "login failed", cause)
}
