package protocol

import "testing"
import "bytes"

type testquicpacket struct {
	positiveTest         bool
	data                 []byte
	packetType           QuicPacketType
	flagPublicReset      bool                      // Public Header field
	flagVersion          bool                      // Public Header field
	version              QuicVersion               // Public Header field
	connId               QuicConnectionID          // Public Header field
	seqNum               QuicPacketSequenceNumber  // Public Header field
	nonceProof           QuicPublicResetNonceProof // Public Reset field
	rejectedseqnum       QuicPacketSequenceNumber  // Public Reset Field
	flagFecPacket        bool                      // Private Header field
	flagFecGroup         bool                      // Private Header field
	flagEntropy          bool                      // Private Header field
	fecGroupNumberOffset QuicFecGroupNumberOffset  // Private Header field
	fecRedundancy        []byte                    // FEC Packet
}

var tests_quicpacket = []testquicpacket{
	// Public Reset packet
	{true, []byte{
		QUICFLAG_PUBLICRESET | QUICFLAG_CONNID_64bit, // Public flags
		0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // Connection ID (64-bit)
		0x50, 0x52, 0x53, 0x54, // Tag 'PRST'
		0x02, 0x00, 0x00, 0x00, // Num entries (uint16) + 2 bytes of padding
		0x52, 0x4e, 0x4f, 0x4e, // Tag 'RNON'
		0x08, 0x00, 0x00, 0x00, //     'RNON' offset
		0x52, 0x53, 0x45, 0x51, // Tag 'RSEQ'
		0x10, 0x00, 0x00, 0x00, //     'RSEQ' offset
		0xde, 0xda, 0xfe, 0xce, 0xbe, 0xba, 0xfe, 0xca, // RNON value
		0xdd, 0xcc, 0xbb, 0xaa, 0x0d, 0x0c, 0x0b, 0x0a}, // Rejected Sequence Number
		QUICPACKETTYPE_PUBLICRESET, // packet type
		true,               // flag Public Reset
		false,              // flag Version
		0,                  // Version
		0x1122334455667788, // Connection ID
		0,                  // Sequence Number
		0xcafebabecefedade, // Nonce Proof (public reset)
		0x0a0b0c0daabbccdd, // Rejected Sequence Number (public reset)
		false,              // FEC Packet flag
		false,              // FEC Group flag
		false,              // Entropy flag
		0,                  // FEC Group Number offset
		nil},               // FEC Redundancy
	{false, []byte{ // Bad message tag 'QRST'
		QUICFLAG_PUBLICRESET | QUICFLAG_CONNID_64bit, // Public flags
		0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // Connection ID (64-bit)
		0x51, 0x52, 0x53, 0x54, // Tag 'QRST'
		0x02, 0x00, 0x00, 0x00, // Num entries (uint16) + 2 bytes of padding
		0x52, 0x4e, 0x4f, 0x4e, // Tag 'RNON'
		0x08, 0x00, 0x00, 0x00, //     'RNON' offset
		0x52, 0x53, 0x45, 0x51, // Tag 'RSEQ'
		0x10, 0x00, 0x00, 0x00, //     'RSEQ' offset
		0xde, 0xda, 0xfe, 0xce, 0xbe, 0xba, 0xfe, 0xca, // RNON value
		0xdd, 0xcc, 0xbb, 0xaa, 0x0d, 0x0c, 0x0b, 0x0a}, // Rejected Sequence Number
		QUICPACKETTYPE_PUBLICRESET, // packet type
		true,               // flag Public Reset
		false,              // flag Version
		0,                  // Version
		0x1122334455667788, // Connection ID
		0,                  // Sequence Number
		0xcafebabecefedade, // Nonce Proof (public reset)
		0x0a0b0c0daabbccdd, // Rejected Sequence Number (public reset)
		false,              // FEC Packet flag
		false,              // FEC Group flag
		false,              // Entropy flag
		0,                  // FEC Group Number offset
		nil},               // FEC Redundancy
	{false, []byte{ // Missing 'RNON' tag
		QUICFLAG_PUBLICRESET | QUICFLAG_CONNID_64bit, // Public flags
		0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // Connection ID (64-bit)
		0x50, 0x52, 0x53, 0x54, // Tag 'PRST'
		0x02, 0x00, 0x00, 0x00, // Num entries (uint16) + 2 bytes of padding
		0x52, 0x4e, 0x4f, 0x4f, // Tag 'RNOO'
		0x08, 0x00, 0x00, 0x00, //     'RNOO' offset
		0x52, 0x53, 0x45, 0x51, // Tag 'RSEQ'
		0x10, 0x00, 0x00, 0x00, //     'RSEQ' offset
		0xde, 0xda, 0xfe, 0xce, 0xbe, 0xba, 0xfe, 0xca, // RNOO value
		0xdd, 0xcc, 0xbb, 0xaa, 0x0d, 0x0c, 0x0b, 0x0a}, // Rejected Sequence Number
		QUICPACKETTYPE_PUBLICRESET, // packet type
		true,               // flag Public Reset
		false,              // flag Version
		0,                  // Version
		0x1122334455667788, // Connection ID
		0,                  // Sequence Number
		0xcafebabecefedade, // Nonce Proof (public reset)
		0x0a0b0c0daabbccdd, // Rejected Sequence Number (public reset)
		false,              // FEC Packet flag
		false,              // FEC Group flag
		false,              // Entropy flag
		0,                  // FEC Group Number offset
		nil},               // FEC Redundancy
	{false, []byte{ // Bad 'RNON' value size (< 64bit)
		QUICFLAG_PUBLICRESET | QUICFLAG_CONNID_64bit, // Public flags
		0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // Connection ID (64-bit)
		0x50, 0x52, 0x53, 0x54, // Tag 'PRST'
		0x02, 0x00, 0x00, 0x00, // Num entries (uint16) + 2 bytes of padding
		0x52, 0x4e, 0x4f, 0x4e, // Tag 'RNON'
		0x07, 0x00, 0x00, 0x00, //     'RNON' offset
		0x52, 0x53, 0x45, 0x51, // Tag 'RSEQ'
		0x0f, 0x00, 0x00, 0x00, //     'RSEQ' offset
		0xde, 0xda, 0xfe, 0xce, 0xbe, 0xba, 0xfe, // RNON value
		0xdd, 0xcc, 0xbb, 0xaa, 0x0d, 0x0c, 0x0b, 0x0a}, // Rejected Sequence Number
		QUICPACKETTYPE_PUBLICRESET, // packet type
		true,               // flag Public Reset
		false,              // flag Version
		0,                  // Version
		0x1122334455667788, // Connection ID
		0,                  // Sequence Number
		0xfebabecefedade,   // Nonce Proof (public reset)
		0x0a0b0c0daabbccdd, // Rejected Sequence Number (public reset)
		false,              // FEC Packet flag
		false,              // FEC Group flag
		false,              // Entropy flag
		0,                  // FEC Group Number offset
		nil},               // FEC Redundancy
	{false, []byte{ // Bad 'RNON' value size (> 64bit)
		QUICFLAG_PUBLICRESET | QUICFLAG_CONNID_64bit, // Public flags
		0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // Connection ID (64-bit)
		0x50, 0x52, 0x53, 0x54, // Tag 'PRST'
		0x02, 0x00, 0x00, 0x00, // Num entries (uint16) + 2 bytes of padding
		0x52, 0x4e, 0x4f, 0x4e, // Tag 'RNON'
		0x09, 0x00, 0x00, 0x00, //     'RNON' offset
		0x52, 0x53, 0x45, 0x51, // Tag 'RSEQ'
		0x11, 0x00, 0x00, 0x00, //     'RSEQ' offset
		0xde, 0xda, 0xfe, 0xce, 0xbe, 0xba, 0xfe, 0xca, 0x00, // RNON value
		0xdd, 0xcc, 0xbb, 0xaa, 0x0d, 0x0c, 0x0b, 0x0a}, // Rejected Sequence Number
		QUICPACKETTYPE_PUBLICRESET, // packet type
		true,               // flag Public Reset
		false,              // flag Version
		0,                  // Version
		0x1122334455667788, // Connection ID
		0,                  // Sequence Number
		0xcafebabecefedade, // Nonce Proof (public reset)
		0x0a0b0c0daabbccdd, // Rejected Sequence Number (public reset)
		false,              // FEC Packet flag
		false,              // FEC Group flag
		false,              // Entropy flag
		0,                  // FEC Group Number offset
		nil},               // FEC Redundancy
	{false, []byte{ // Missing 'RSEQ' tag
		QUICFLAG_PUBLICRESET | QUICFLAG_CONNID_64bit, // Public flags
		0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // Connection ID (64-bit)
		0x50, 0x52, 0x53, 0x54, // Tag 'PRST'
		0x02, 0x00, 0x00, 0x00, // Num entries (uint16) + 2 bytes of padding
		0x52, 0x4e, 0x4f, 0x4e, // Tag 'RNON'
		0x08, 0x00, 0x00, 0x00, //     'RNON' offset
		0x52, 0x53, 0x46, 0x51, // Tag 'RSFQ'
		0x10, 0x00, 0x00, 0x00, //     'RSFQ' offset
		0xde, 0xda, 0xfe, 0xce, 0xbe, 0xba, 0xfe, 0xca, // RNON value
		0xdd, 0xcc, 0xbb, 0xaa, 0x0d, 0x0c, 0x0b, 0x0a}, // Rejected Sequence Number
		QUICPACKETTYPE_PUBLICRESET, // packet type
		true,               // flag Public Reset
		false,              // flag Version
		0,                  // Version
		0x1122334455667788, // Connection ID
		0,                  // Sequence Number
		0xcafebabecefedade, // Nonce Proof (public reset)
		0,                  // Rejected Sequence Number (public reset)
		false,              // FEC Packet flag
		false,              // FEC Group flag
		false,              // Entropy flag
		0,                  // FEC Group Number offset
		nil},               // FEC Redundancy
	{false, []byte{ // Bad 'RSEQ' value size (< 64bit)
		QUICFLAG_PUBLICRESET | QUICFLAG_CONNID_64bit, // Public flags
		0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // Connection ID (64-bit)
		0x50, 0x52, 0x53, 0x54, // Tag 'PRST'
		0x02, 0x00, 0x00, 0x00, // Num entries (uint16) + 2 bytes of padding
		0x52, 0x4e, 0x4f, 0x4e, // Tag 'RNON'
		0x08, 0x00, 0x00, 0x00, //     'RNON' offset
		0x52, 0x53, 0x45, 0x51, // Tag 'RSEQ'
		0x0f, 0x00, 0x00, 0x00, //     'RSEQ' offset
		0xde, 0xda, 0xfe, 0xce, 0xbe, 0xba, 0xfe, 0xca, // RNON value
		0xdd, 0xcc, 0xbb, 0xaa, 0x0d, 0x0c, 0x0b}, // Rejected Sequence Number
		QUICPACKETTYPE_PUBLICRESET, // packet type
		true,               // flag Public Reset
		false,              // flag Version
		0,                  // Version
		0x1122334455667788, // Connection ID
		0,                  // Sequence Number
		0xcafebabecefedade, // Nonce Proof (public reset)
		0x0b0c0daabbccdd,   // Rejected Sequence Number (public reset)
		false,              // FEC Packet flag
		false,              // FEC Group flag
		false,              // Entropy flag
		0,                  // FEC Group Number offset
		nil},               // FEC Redundancy
	{false, []byte{ // Bad 'RSEQ' value size (> 64bit)
		QUICFLAG_PUBLICRESET | QUICFLAG_CONNID_64bit, // Public flags
		0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // Connection ID (64-bit)
		0x50, 0x52, 0x53, 0x54, // Tag 'PRST'
		0x02, 0x00, 0x00, 0x00, // Num entries (uint16) + 2 bytes of padding
		0x52, 0x4e, 0x4f, 0x4e, // Tag 'RNON'
		0x08, 0x00, 0x00, 0x00, //     'RNON' offset
		0x52, 0x53, 0x45, 0x51, // Tag 'RSEQ'
		0x11, 0x00, 0x00, 0x00, //     'RSEQ' offset
		0xde, 0xda, 0xfe, 0xce, 0xbe, 0xba, 0xfe, 0xca, // RNON value
		0xdd, 0xcc, 0xbb, 0xaa, 0x0d, 0x0c, 0x0b, 0x0a, 0x00}, // Rejected Sequence Number
		QUICPACKETTYPE_PUBLICRESET, // packet type
		true,               // flag Public Reset
		false,              // flag Version
		0,                  // Version
		0x1122334455667788, // Connection ID
		0,                  // Sequence Number
		0xcafebabecefedade, // Nonce Proof (public reset)
		0x0a0b0c0daabbccdd, // Rejected Sequence Number (public reset)
		false,              // FEC Packet flag
		false,              // FEC Group flag
		false,              // Entropy flag
		0,                  // FEC Group Number offset
		nil},               // FEC Redundancy

	// Version Negotiation packet

	// FEC packet
	{true, []byte{
		QUICFLAG_CONNID_64bit | QUICFLAG_SEQNUM_8bit, // Public flags
		0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // Connection ID (64-bit)
		0x42, // Sequence Number (8-bit)
		QUICFLAG_FECPACKET | QUICFLAG_FECGROUP, // Private flags
		0x13,              // FEC Group Number offset
		0xab, 0xcd, 0xef}, // FEC Redundancy data
		QUICPACKETTYPE_FEC, // packet type
		false,              // flag Public Reset
		false,              // flag Version
		0,                  // Version
		0x1122334455667788, // Connection ID
		0x42,               // Sequence Number
		0,                  // Nonce Proof (public reset)
		0,                  // Rejected Sequence Number (public reset)
		true,               // FEC Packet flag
		true,               // FEC Group flag
		false,              // Entropy flag
		0x13,               // FEC Group Number offset
		[]byte{0xab, 0xcd, 0xef}}, // FEC Redundancy
	{false, []byte{
		QUICFLAG_CONNID_64bit | QUICFLAG_SEQNUM_8bit, // Public flags
		0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // Connection ID (64-bit)
		0x42,               // Sequence Number (8-bit)
		QUICFLAG_FECPACKET, // Private flags
		// No FEC Group Number offset
		0xab, 0xcd, 0xef}, // FEC Redundancy data
		QUICPACKETTYPE_FEC, // packet type
		false,              // flag Public Reset
		false,              // flag Version
		0,                  // Version
		0x1122334455667788, // Connection ID
		0x42,               // Sequence Number
		0,                  // Nonce Proof (public reset)
		0,                  // Rejected Sequence Number (public reset)
		true,               // FEC Packet flag
		true,               // FEC Group flag
		false,              // Entropy flag
		0x13,               // FEC Group Number offset
		[]byte{0xab, 0xcd, 0xef}}, // FEC Redundancy
	{false, []byte{
		QUICFLAG_CONNID_64bit | QUICFLAG_SEQNUM_8bit, // Public flags
		0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // Connection ID (64-bit)
		0x42, // Sequence Number (8-bit)
		QUICFLAG_FECPACKET | QUICFLAG_FECGROUP, // Private flags
		0x13}, // FEC Group Number offset
		// No FEC Redundancy data
		QUICPACKETTYPE_FEC, // packet type
		false,              // flag Public Reset
		false,              // flag Version
		0,                  // Version
		0x1122334455667788, // Connection ID
		0x42,               // Sequence Number
		0,                  // Nonce Proof (public reset)
		0,                  // Rejected Sequence Number (public reset)
		true,               // FEC Packet flag
		true,               // FEC Group flag
		false,              // Entropy flag
		0x13,               // FEC Group Number offset
		nil},               // FEC Redundancy

	// Frame packet
}

func Test_QuicPacket_ParseData(t *testing.T) {
	var packet QuicPacket
	var fgno QuicFecGroupNumberOffset

	for i, v := range tests_quicpacket {
		s, err := packet.ParseData(v.data)
		if v.positiveTest {
			if err != nil {
				t.Errorf("QuicPacket.ParseData : error %s in test n°%v with data[%v]%x", err, i, len(v.data), v.data[:s])
			}
			// Public Header checking
			if packet.GetPacketType() != v.packetType {
				t.Errorf("QuicPacket.ParseData : bad packet type %v in test n°%v with data[%v]%x", packet.GetPacketType(), i, len(v.data), v.data[:s])
			}
			if packet.publicHeader.GetVersionFlag() != v.flagVersion {
				t.Errorf("QuicPacket.ParseData : invalid Version flag =%v in test n°%v with data[%v]%x", packet.publicHeader.GetVersionFlag(), i, len(v.data), v.data[:s])
			}
			if packet.publicHeader.GetVersion() != v.version {
				t.Errorf("QuicPacket.ParseData : invalid Connection ID %x in test n°%v with data[%v]%x", packet.publicHeader.GetVersion(), i, len(v.data), v.data[:s])
			}
			if packet.publicHeader.GetConnectionID() != v.connId {
				t.Errorf("QuicPacket.ParseData : invalid Connection ID %x in test n°%v with data[%v]%x", packet.publicHeader.GetConnectionID(), i, len(v.data), v.data[:s])
			}
			if packet.publicHeader.GetSequenceNumber() != v.seqNum {
				t.Errorf("QuicPacket.ParseData : invalid Sequence Number %x in test n°%v with data[%v]%x", packet.publicHeader.GetSequenceNumber(), i, len(v.data), v.data[:s])
			}
			// Public Reset checking
			if packet.publicReset.GetNonceProof() != v.nonceProof {
				t.Errorf("QuicPacket.ParseData : invalid Nonce Proof %x in test n°%v with data[%v]%x", packet.publicReset.GetNonceProof(), i, len(v.data), v.data[:s])
			}
			if packet.publicReset.GetRejectedSequenceNumber() != v.rejectedseqnum {
				t.Errorf("QuicPacket.ParseData : invalid Rejected Sequence Number %x in test n°%v with data[%v]%x", packet.publicReset.GetRejectedSequenceNumber(), i, len(v.data), v.data[:s])
			}
			// Private Header checking
			if packet.privateHeader.GetFecPacketFlag() != v.flagFecPacket {
				t.Errorf("QuicPacket.ParseData : invalid FEC Packet flag in test n°%v with data[%v]%x", i, len(v.data), v.data[:s])
			}
			if packet.privateHeader.GetFecGroupFlag() != v.flagFecGroup {
				t.Errorf("QuicPacket.ParseData : invalid FEC Group flag in test n°%v with data[%v]%x", i, len(v.data), v.data[:s])
			}
			if packet.privateHeader.GetEntropyFlag() != v.flagEntropy {
				t.Errorf("QuicPacket.ParseData : invalid Entropy flag in test n°%v with data[%v]%x", i, len(v.data), v.data[:s])
			}
			if v.flagFecGroup {
				fgno, err = packet.privateHeader.GetFecGroupNumberOffset()
				if err != nil {
					t.Errorf("QuicPacket.ParseData : error %s in test n°%v with data[%v]%x", err, i, len(v.data), v.data[:s])
				}
				if fgno != v.fecGroupNumberOffset {
					t.Errorf("QuicPacket.ParseData : invalid FEC Group Number offset %x in test n°%v with data[%v]%x", fgno, i, len(v.data), v.data[:s])
				}
			}
		} else if err == nil {
			t.Errorf("QuicPacket.ParseData : missing error in test n°%v with data[%v]%x", i, s, v.data[:s])
		}
		packet.Erase()
	}
}

func Test_QuicPacket_SerializeData(t *testing.T) {
	var packet QuicPacket

	for i, v := range tests_quicpacket {
		if v.positiveTest {
			// setup packet type
			packet.SetPacketType(v.packetType)
			// setup Public Header
			packet.publicHeader.SetPublicResetFlag(v.flagPublicReset)
			packet.publicHeader.SetPublicResetFlag(v.flagVersion)
			packet.publicHeader.SetVersion(v.version)
			packet.publicHeader.SetConnectionID(v.connId)
			packet.publicHeader.SetSequenceNumber(v.seqNum)
			packet.publicHeader.SetConnectionIdSize(parsePublicheaderConnectionIdSize[(v.data[0]>>2)&0x0f])
			packet.publicHeader.SetSequenceNumberSize(parsePublicheaderSequenceNumberSize[(v.data[0]>>2)&0x0f])
			// setup Private Header
			packet.privateHeader.SetFecPacketFlag(v.flagFecPacket)
			packet.privateHeader.SetFecGroupFlag(v.flagFecGroup)
			packet.privateHeader.SetEntropyFlag(v.flagEntropy)
			packet.privateHeader.SetFecGroupNumberOffset(v.fecGroupNumberOffset)
			// setup Public Reset Packet
			packet.publicReset.SetNonceProof(v.nonceProof)
			packet.publicReset.SetRejectedSequenceNumber(v.rejectedseqnum)
			// setup FEC Packet
			packet.fecPacket.SetRedundancyData(v.fecRedundancy)
			// TO DO: setup Frame Packet
			// Get and check the serialized data
			data, err := packet.GetSerializedData()
			if err != nil {
				t.Errorf("QuicPacket.GetSerializedData = error %s while serialized data in test n°%v", err, i)
			}
			if len(data) != len(v.data) {
				t.Errorf("QuicPacket.GetSerializedData = invalid serialized size in test n°%v with data[%v]%x", i, len(data), data)
			}
			if !bytes.Equal(data, v.data) {
				t.Errorf("QuicPacket.GetSerializedData = invalid serialized data in test n°%v with data[%v]%x", i, len(data), data)
			}

		}
		packet.Erase()
	}
}
