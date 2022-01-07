package protocol

const (
	preloginVERSION         = 0
	preloginENCRYPTION      = 1
	preloginINSTOPT         = 2
	preloginTHREADID        = 3
	preloginMARS            = 4
	preloginTRACEID         = 5
	preloginFEDAUTHREQUIRED = 6
	preloginNONCEOPT        = 7
	preloginTERMINATOR      = 0xff
)

const (
	// EncryptionOff is a PRELOGIN option indicating that TLS is available but off.
	EncryptionOff = 0
	// EncryptionOn is a PRELOGIN option indicating that TLS is available and on.
	EncryptionOn = 1
	// EncryptionNotSupported is a PRELOGIN option indicating that TLS is not available.
	EncryptionNotSupported = 2
	// EncryptionRequired is a PRELOGIN option indicating that TLS is required.
	EncryptionRequired = 3
)

const (
	verTDS70     = 0x70000000
	verTDS71     = 0x71000000
	verTDS71rev1 = 0x71000001
	verTDS72     = 0x72090002
	verTDS73A    = 0x730A0003
	verTDS73     = verTDS73A
	verTDS73B    = 0x730B0003
	verTDS74     = 0x74000004
)
