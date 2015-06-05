package crypto

type MessageTag uint32

// Maximum numer of entries in a Message
const MaxNumEntries = 128

// QUIC tag values
const (
	// Client message tag
	TagCHLO = 'C' + ('H' << 8) + ('L' << 16) + ('O' << 24) // Client Hello message tag

	// Server message tag
	TagSHLO = 'S' + ('H' << 8) + ('L' << 16) + ('O' << 24) // Server Hello message tag
	TagREJ  = 'R' + ('E' << 8) + ('J' << 16) + (0 << 24)   // Server Rejection message tag
	TAGSCUP = 'S' + ('C' << 8) + ('U' << 16) + ('P' << 24) // Server Config Update message tag can be used only after handshake complete

	// Content tags
	TagPAD  = 'P' + ('A' << 8) + ('D' << 16) + (0 << 24)   // Padding tag
	TagSNI  = 'S' + ('N' << 8) + ('I' << 16) + (0 << 24)   // Server Name Indication
	TagSTK  = 'S' + ('T' << 8) + ('K' << 16) + (0 << 24)   // Source-address Token
	TagPDMD = 'P' + ('D' << 8) + ('M' << 16) + ('D' << 24) // Proof demand
	TagCCS  = 'C' + ('C' << 8) + ('S' << 16) + (0 << 24)   // Common Certificates Sets
	TagCCRT = 'C' + ('C' << 8) + ('R' << 16) + ('T' << 24) // Cached Certificates
	TagVERS = 'V' + ('E' << 8) + ('R' << 16) + ('S' << 24) // Version
	TagSCFG = 'S' + ('C' << 8) + ('F' << 16) + ('G' << 24) // Server Config
	TagSNO  = 'S' + ('N' << 8) + ('O' << 16) + (0 << 24)   // Server Nonce
	TagCRT  = 'C' + ('R' << 8) + ('T' << 16) + (255 << 24) // Certificate Chain
	TagPROF = 'P' + ('R' << 8) + ('O' << 16) + ('F' << 24) // Proof of Authenticity
	TagSCID = 'S' + ('C' << 8) + ('I' << 16) + ('D' << 24) // Server Config ID

	TagKEXS = 'K' + ('E' << 8) + ('X' << 16) + ('S' << 24) // Key Exchange algorithms :
	TagNULL = 'N' + ('U' << 8) + ('L' << 16) + ('L' << 24) //     null algorithm = no encryption with FNV1A-128 12-byte tag
	TagC255 = 'C' + ('2' << 8) + ('5' << 16) + ('5' << 24) //     Curve25519
	TagP256 = 'P' + ('2' << 8) + ('5' << 16) + ('6' << 24) //     P-256

	TagPUBS = 'P' + ('U' << 8) + ('B' << 16) + ('S' << 24) // List of public values, 24-bit little endian length prefixed, in same order as in KEXS

	TagAEAD = 'A' + ('E' << 8) + ('A' << 16) + ('D' << 24) // Authenticated Encryption algorithms :
	TagAESG = 'A' + ('E' << 8) + ('S' << 16) + ('G' << 24) //     AES-GCM with 12-byte tag
	TagS20P = 'S' + ('2' << 8) + ('0' << 16) + ('P' << 24) //     Salsa20 with Poly1305

	TagORBT = 'O' + ('R' << 8) + ('B' << 16) + ('T' << 24) // Orbit, 8-byte opaque value that identifies strike-register
	TagEXPY = 'E' + ('X' << 8) + ('P' << 16) + ('Y' << 24) // Expiry, 64-bit expiry time for server config in UNIX epoch-seconds
	TagNONC = 'N' + ('O' << 8) + ('N' << 16) + ('C' << 24) // Client Nonce, 32-bytes consisting of 4 bytes of timestamp(big-endian, UNIX epoch-seconds), 8-bytes of server orbit and 20 bytes of random data

	TagCETV = 'C' + ('E' << 8) + ('T' << 16) + ('V' << 24) // Client Encrypted Tag-Values :
	TagCIDK = 'C' + ('I' << 8) + ('D' << 16) + ('K' << 24) //     ChannelID key, a pair of 32-bytes big-endian numbers  which together specify an (x,y) pair = point on P-256 curve and an ECDSA public key
	TagCIDS = 'C' + ('I' << 8) + ('D' << 16) + ('S' << 24) //     ChannelID signature, a pair of 32-bytes big-endian numbers which together specify the (r,s) pair of an ECDSA signature of the HKDF input

	TagX509 = 'X' + ('5' << 8) + ('0' << 16) + ('9' << 24) // X.509 certificate, all key types
	TagX59R = 'X' + ('5' << 8) + ('9' << 16) + ('R' << 24) // X.509 certificate, RSA keys only

	TagRREJ = 'R' + ('R' << 8) + ('E' << 16) + ('J' << 24) // Reasons for server sending rejection message tag
	TagCADR = 'C' + ('A' << 8) + ('D' << 16) + ('R' << 24) // Client IP address and port

	TagRNON = 'R' + ('N' << 8) + ('O' << 16) + ('N' << 24) // Public reset nonce proof
	TagRSEQ = 'R' + ('S' << 8) + ('E' << 16) + ('Q' << 24) // Rejected sequence number

	TagCOPT = 'C' + ('O' << 8) + ('P' << 16) + ('T' << 24) // Connection Options
	TagICSL = 'I' + ('C' << 8) + ('S' << 16) + ('L' << 24) //     Idle connection state lifetime
	TagSCLS = 'S' + ('C' << 8) + ('L' << 16) + ('S' << 24) //     Silently close on timeout
	TagMSPC = 'M' + ('S' << 8) + ('P' << 16) + ('C' << 24) //     Max streams per connection
	TagIRTT = 'I' + ('R' << 8) + ('T' << 16) + ('T' << 24) //     Estimated initial RTT in us
	TagSWND = 'S' + ('W' << 8) + ('N' << 16) + ('D' << 24) //     Server’s Initial congestion window
	TagSFCW = 'S' + ('F' << 8) + ('C' << 16) + ('W' << 24) //     Initial stream flow control receive window
	TagCFCW = 'C' + ('F' << 8) + ('C' << 16) + ('W' << 24) //     Initial session/connection flow control receive window

// new Tag = '' + ('' << 8) + ('' << 16) + ('' << 24) //
)

// Message struct containing message tag value and associated ta-values pairs
type Message struct {
	msgTag MessageTag
	tags   []MessageTag
	values [][]byte
}

// NewMessage is a Message factory
func NewMessage(messagetag MessageTag, tags []MessageTag, values [][]byte) *Message {
	if len(tags) != len(values) {
		return nil
	}
	m := new(Message)
	m.msgTag = messagetag
	m.tags = tags
	m.values = values
	return m
}

// Tag return the message tag of the crypto.Message
func (this *Message) GetMessageTag() MessageTag {
	return this.msgTag
}

// Tag return the message tag of the crypto.Message
func (this *Message) GetNumEntries() uint16 {
	return uint16(len(this.tags))
}

// Contains method return 'true' and the associated tag value []byte if the message contains the requested tag, otherwise returns 'false' and nil
func (this *Message) Contains(t MessageTag) (bool, []byte) {
	for i, v := range this.tags {
		if v == t {
			return true, this.values[i]
		}
	}
	return false, nil
}
