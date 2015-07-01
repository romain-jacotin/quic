package protocol

import "testing"
import "bytes"

/*

     0        1        2        3        4         8
+--------+--------+--------+--------+--------+--   --+
| Public |    Connection ID (64)                ...  | ->
|Flags(8)|                                           |
+--------+--------+--------+--------+--------+--   --+

     9       10       11        12       13      14
+--------+--------+--------+--------+--------+--------+---
|      Quic Tag (32)                |  Tag value map      ... ->
|         (PRST)                    |  (variable length)
+--------+--------+--------+--------+--------+--------+---


Public flags:
+---+---+---+---+---+---+---+---+
| 0 | 0 | SeqNum| ConnID|Rst|Ver|
+---+---+---+---+---+---+---+---+

TagPRST = 0x54535250
TagRNON = 0x4e4f4e52
TagRSEQ = 0x51455352

*/

type testquicpublicresetpacket struct {
	positiveTest   bool
	data           []byte
	nonceProof     QuicPublicResetNonceProof
	rejectedseqnum QuicPacketSequenceNumber
}

var tests_quicpublicresetpacket = []testquicpublicresetpacket{
	{true, []byte{
		0x50, 0x52, 0x53, 0x54, // Tag 'PRST'
		0x02, 0x00, 0x00, 0x00, // Num entries (uint16) + 2 bytes of padding
		0x52, 0x4e, 0x4f, 0x4e, // Tag 'RNON'
		0x08, 0x00, 0x00, 0x00, //     'RNON' offset
		0x52, 0x53, 0x45, 0x51, // Tag 'RSEQ'
		0x10, 0x00, 0x00, 0x00, //     'RSEQ' offset
		0xde, 0xda, 0xfe, 0xce, 0xbe, 0xba, 0xfe, 0xca, // RNON value
		0xdd, 0xcc, 0xbb, 0xaa, 0x0d, 0x0c, 0x0b, 0x0a}, // Rejected Sequence Number
		0xcafebabecefedade, 0x0a0b0c0daabbccdd},
	// Bad message tag 'QRST'
	{false, []byte{
		0x51, 0x52, 0x53, 0x54, // Tag 'QRST'
		0x02, 0x00, 0x00, 0x00, // Num entries (uint16) + 2 bytes of padding
		0x52, 0x4e, 0x4f, 0x4e, // Tag 'RNON'
		0x08, 0x00, 0x00, 0x00, //     'RNON' offset
		0x52, 0x53, 0x45, 0x51, // Tag 'RSEQ'
		0x10, 0x00, 0x00, 0x00, //     'RSEQ' offset
		0xde, 0xda, 0xfe, 0xce, 0xbe, 0xba, 0xfe, 0xca, // RNON value
		0xdd, 0xcc, 0xbb, 0xaa, 0x0d, 0x0c, 0x0b, 0x0a}, // Rejected Sequence Number
		0xcafebabecefedade, 0x0a0b0c0daabbccdd},
	// Missing 'RNON' tag
	{false, []byte{
		0x50, 0x52, 0x53, 0x54, // Tag 'PRST'
		0x02, 0x00, 0x00, 0x00, // Num entries (uint16) + 2 bytes of padding
		0x52, 0x4e, 0x4f, 0x4f, // Tag 'RNOO'
		0x08, 0x00, 0x00, 0x00, //     'RNOO' offset
		0x52, 0x53, 0x45, 0x51, // Tag 'RSEQ'
		0x10, 0x00, 0x00, 0x00, //     'RSEQ' offset
		0xde, 0xda, 0xfe, 0xce, 0xbe, 0xba, 0xfe, 0xca, // RNOO value
		0xdd, 0xcc, 0xbb, 0xaa, 0x0d, 0x0c, 0x0b, 0x0a}, // Rejected Sequence Number
		0xcafebabecefedade, 0x0a0b0c0daabbccdd},
	// Bad 'RNON' value size (< 64bit)
	{false, []byte{
		0x50, 0x52, 0x53, 0x54, // Tag 'PRST'
		0x02, 0x00, 0x00, 0x00, // Num entries (uint16) + 2 bytes of padding
		0x52, 0x4e, 0x4f, 0x4e, // Tag 'RNON'
		0x07, 0x00, 0x00, 0x00, //     'RNON' offset
		0x52, 0x53, 0x45, 0x51, // Tag 'RSEQ'
		0x0f, 0x00, 0x00, 0x00, //     'RSEQ' offset
		0xde, 0xda, 0xfe, 0xce, 0xbe, 0xba, 0xfe, // RNON value
		0xdd, 0xcc, 0xbb, 0xaa, 0x0d, 0x0c, 0x0b, 0x0a}, // Rejected Sequence Number
		0xfebabecefedade, 0x0a0b0c0daabbccdd},
	// Bad 'RNON' value size (> 64bit)
	{false, []byte{
		0x50, 0x52, 0x53, 0x54, // Tag 'PRST'
		0x02, 0x00, 0x00, 0x00, // Num entries (uint16) + 2 bytes of padding
		0x52, 0x4e, 0x4f, 0x4e, // Tag 'RNON'
		0x09, 0x00, 0x00, 0x00, //     'RNON' offset
		0x52, 0x53, 0x45, 0x51, // Tag 'RSEQ'
		0x11, 0x00, 0x00, 0x00, //     'RSEQ' offset
		0xde, 0xda, 0xfe, 0xce, 0xbe, 0xba, 0xfe, 0xca, 0x00, // RNON value
		0xdd, 0xcc, 0xbb, 0xaa, 0x0d, 0x0c, 0x0b, 0x0a}, // Rejected Sequence Number
		0xcafebabecefedade, 0x0a0b0c0daabbccdd},
	// Missing 'RSEQ' tag
	{false, []byte{
		0x50, 0x52, 0x53, 0x54, // Tag 'PRST'
		0x02, 0x00, 0x00, 0x00, // Num entries (uint16) + 2 bytes of padding
		0x52, 0x4e, 0x4f, 0x4e, // Tag 'RNON'
		0x08, 0x00, 0x00, 0x00, //     'RNON' offset
		0x52, 0x53, 0x46, 0x51, // Tag 'RSFQ'
		0x10, 0x00, 0x00, 0x00, //     'RSFQ' offset
		0xde, 0xda, 0xfe, 0xce, 0xbe, 0xba, 0xfe, 0xca, // RNON value
		0xdd, 0xcc, 0xbb, 0xaa, 0x0d, 0x0c, 0x0b, 0x0a}, // Rejected Sequence Number
		0xcafebabecefedade, 0x0a0b0c0daabbccdd},
	// Bad 'RSEQ' value size (< 64bit)
	{false, []byte{
		0x50, 0x52, 0x53, 0x54, // Tag 'PRST'
		0x02, 0x00, 0x00, 0x00, // Num entries (uint16) + 2 bytes of padding
		0x52, 0x4e, 0x4f, 0x4e, // Tag 'RNON'
		0x08, 0x00, 0x00, 0x00, //     'RNON' offset
		0x52, 0x53, 0x45, 0x51, // Tag 'RSEQ'
		0x0f, 0x00, 0x00, 0x00, //     'RSEQ' offset
		0xde, 0xda, 0xfe, 0xce, 0xbe, 0xba, 0xfe, 0xca, // RNON value
		0xdd, 0xcc, 0xbb, 0xaa, 0x0d, 0x0c, 0x0b}, // Rejected Sequence Number
		0xcafebabecefedade, 0x0b0c0daabbccdd},
	// Bad 'RSEQ' value size (> 64bit)
	{false, []byte{
		0x50, 0x52, 0x53, 0x54, // Tag 'PRST'
		0x02, 0x00, 0x00, 0x00, // Num entries (uint16) + 2 bytes of padding
		0x52, 0x4e, 0x4f, 0x4e, // Tag 'RNON'
		0x08, 0x00, 0x00, 0x00, //     'RNON' offset
		0x52, 0x53, 0x45, 0x51, // Tag 'RSEQ'
		0x11, 0x00, 0x00, 0x00, //     'RSEQ' offset
		0xde, 0xda, 0xfe, 0xce, 0xbe, 0xba, 0xfe, 0xca, // RNON value
		0xdd, 0xcc, 0xbb, 0xaa, 0x0d, 0x0c, 0x0b, 0x0a, 0x00}, // Rejected Sequence Number
		0xcafebabecefedade, 0x0a0b0c0daabbccdd},
}

func Test_QuicPublicRestPacket_ParseData(t *testing.T) {
	var reset QuicPublicResetPacket

	for i, v := range tests_quicpublicresetpacket {
		s, err := reset.ParseData(v.data)
		if v.positiveTest {
			if err != nil {
				t.Errorf("QuicPublicRestPacket.ParseData : error %s in test %x with data[%v]%x", err, i, len(v.data), v.data)
			}
			if s != len(v.data) {
				t.Errorf("QuicPublicRestPacket.ParseData : invalid size %v in test %x with data[%v]%x", s, i, len(v.data), v.data)
			}
			if v.nonceProof != reset.GetNonceProof() {
				t.Errorf("QuicPublicRestPacket.ParseData : invalid proof %x in test %x with data[%v]%x", reset.GetNonceProof(), i, len(v.data), v.data)
			}
			if v.rejectedseqnum != reset.GetRejectedSequenceNumber() {
				t.Errorf("QuicPublicRestPacket.ParseData : invalid rejected sequence number %x in test %x with data[%v]%x", reset.GetRejectedSequenceNumber(), i, len(v.data), v.data)
			}
		} else if err == nil {
			t.Error("QuicPublicRestPacket.ParseData : missing error in test %x with data[%v]%x", i, len(v.data), v.data)
		}
	}
}

func Test_QuicPublicRestPacket_GetSerializedData(t *testing.T) {
	var reset QuicPublicResetPacket

	data := make([]byte, 40)
	for i, v := range tests_quicpublicresetpacket {
		if v.positiveTest {
			reset.SetNonceProof(v.nonceProof)
			reset.SetRejectedSequenceNumber(v.rejectedseqnum)
			s, err := reset.GetSerializedData(data)
			if err != nil {
				t.Errorf("QuicPublicRestPacket.GetSerializedData = error %s while serialized data in test n°%v", err, i)
			}
			if s != len(v.data) {
				t.Errorf("QuicPublicRestPacket.GetSerializedData = invalid serialized size in test n°%v with data[%v]%x", i, s, data[:s])
			}
			if !bytes.Equal(data[:s], v.data) {
				t.Errorf("QuicPublicRestPacket.GetSerializedData = invalid serialized data in test n°%v with data[%v]%x", i, s, data[:s])
			}
			reset.Erase()
		}
	}

}
