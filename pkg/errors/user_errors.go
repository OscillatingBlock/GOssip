package errors

var (
	// Domain errors — used in usecase/repository
	ErrRateLimitExceeded            = InvalidArg("rate limit exceeded")
	ErrUsernameTaken                = AlreadyExists("username is already taken")
	ErrUserNotFound                 = NotFound("user not found")
	ErrInvalidUsername              = InvalidArg("username must be 3-32 chars, lowercase letters, numbers and underscores only")
	ErrInvalidDisplayName           = InvalidArg("display name cannot be empty")
	ErrIdentityKeyMissing           = FailedPrecondition("identity key not registered")
	ErrSignedPreKeyMissing          = FailedPrecondition("signed prekey not uploaded")
	ErrNoPreKeysAvailable           = FailedPrecondition("no one-time prekeys available")
	ErrInvalidChallengeID           = InvalidArg("invalid challenge id")
	ErrInvalidSignedPreKey          = InvalidArg("invalid signed prekey")
	ErrInvalidOneTimePreKey         = InvalidArg("invalid one-time prekey")
	ErrInvalidSignedPreKeySignature = InvalidArg("invalid signed prekey signature")
	ErrInvalidUserID                = InvalidArg("invalid user id")
	ErrInvalidIdentityKey           = InvalidArg("invalid identity key")
	ErrInvalidEncryptionKey         = InvalidArg("invalid encryption key")
	ErrUserOrBundleNotFound         = NotFound("user or prekey bundle not available")
	ErrInvalidQuery                 = InvalidArg("invalid query")
	ErrForbidden                    = Forbidden("forbidden")
)
var (
	ErrChallengeNotFound = InvalidArg("challenge not found")    // 400/404
	ErrChallengeExpired  = InvalidArg("challenge expired")      // 400
	ErrChallengeUsed     = InvalidArg("challenge already used") // 400
	ErrInvalidSignature  = Unauthenticated("invalid signature") // 401
	ErrInvalidChallenge  = InvalidArg("invalid challenge")      // generic fallback
)

var (
	ErrUnauthorized              = Unauthenticated("Unauthenticated")
	ErrInvalidJWTToken           = Unauthenticated("invalid jwt token")
	ErrJWTInvalidClaims          = Unauthenticated("invalid jwt claims")
	ErrJWTExpired                = Unauthenticated("jwt token expired")
	ErrInvalidTokenSigningMethod = Unauthenticated("invalid token signing method")
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
