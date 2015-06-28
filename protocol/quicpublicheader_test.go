package protocol

import "testing"
import "bytes"

/*

     0        1        2        3        4            8
+--------+--------+--------+--------+--------+---    ---+
| Public |    Connection ID (0, 8, 32, or 64)    ...    | ->
|Flags(8)|      (variable length)                       |
+--------+--------+--------+--------+--------+---    ---+

     9       10       11        12
+--------+--------+--------+--------+
|      Quic Version (32)            | ->
|         (optional)                |
+--------+--------+--------+--------+

    13      14       15        16        17       18
+--------+--------+--------+--------+--------+--------+
|         Sequence Number (8, 16, 32, or 48)          |
|                         (variable length)           |
+--------+--------+--------+--------+--------+--------+


Public flags:
+---+---+---+---+---+---+---+---+
| 0 | 0 | SeqNum| ConnID|Rst|Ver|
+---+---+---+---+---+---+---+---+

*/

type testquicpublicheader struct {
	data            []byte
	flagPublicReset bool
	flagVersion     bool
	version         QuicVersion
	connId          QuicConnectionID
	seqNum          QuicPacketSequenceNumber
	positifTest     bool
}

var tests_quicpublicheader = []testquicpublicheader{

	// Tests[0-1] not enough data

	{[]byte{}, true, true, 0x01020304, 0x1122334455667788, 0xaabbccdd0a0b0c0d, false},

	{[]byte{0x66}, true, true, 0x01020304, 0x1122334455667788, 0xaabbccdd0a0b0c0d, false},

	// Tests[2-5] with mixed flags of Version and Public reset

	{[]byte{QUICFLAG_CONNID_0bit | QUICFLAG_SEQNUM_8bit, 0x0d},
		false, false, 0, 0, 0x0d, true},

	{[]byte{QUICFLAG_VERSION | QUICFLAG_CONNID_0bit | QUICFLAG_SEQNUM_8bit, 0x04, 0x03, 0x02, 0x01, 0x0d},
		false, true, 0x01020304, 0, 0x0d, true},

	{[]byte{QUICFLAG_PUBLICRESET | QUICFLAG_CONNID_0bit | QUICFLAG_SEQNUM_8bit, 0x0d},
		true, false, 0, 0, 0x0d, true},

	{[]byte{QUICFLAG_VERSION | QUICFLAG_PUBLICRESET | QUICFLAG_CONNID_0bit | QUICFLAG_SEQNUM_8bit, 0x04, 0x03, 0x02, 0x01, 0x0d},
		true, true, 0x01020304, 0, 0x0d, true},

	// Tests[6-13] with various Connection ID size and Version flags

	{[]byte{QUICFLAG_CONNID_0bit | QUICFLAG_SEQNUM_8bit, 0x0d},
		false, false, 0, 0, 0x0d, true},

	{[]byte{QUICFLAG_CONNID_8bit | QUICFLAG_SEQNUM_8bit, 0x88, 0x0d},

		false, false, 0, 0x88, 0x0d, true},
	{[]byte{QUICFLAG_CONNID_32bit | QUICFLAG_SEQNUM_8bit, 0x88, 0x77, 0x66, 0x55, 0x0d},
		false, false, 0, 0x55667788, 0x0d, true},

	{[]byte{QUICFLAG_CONNID_64bit | QUICFLAG_SEQNUM_8bit, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x0d},
		false, false, 0, 0x1122334455667788, 0x0d, true},

	{[]byte{QUICFLAG_VERSION | QUICFLAG_CONNID_0bit | QUICFLAG_SEQNUM_8bit, 0x04, 0x03, 0x02, 0x01, 0x0d},
		false, true, 0x01020304, 0, 0x0d, true},

	{[]byte{QUICFLAG_VERSION | QUICFLAG_CONNID_8bit | QUICFLAG_SEQNUM_8bit, 0x88, 0x04, 0x03, 0x02, 0x01, 0x0d},
		false, true, 0x01020304, 0x88, 0x0d, true},

	{[]byte{QUICFLAG_VERSION | QUICFLAG_CONNID_32bit | QUICFLAG_SEQNUM_8bit, 0x88, 0x77, 0x66, 0x55, 0x04, 0x03, 0x02, 0x01, 0x0d},
		false, true, 0x01020304, 0x55667788, 0x0d, true},

	{[]byte{QUICFLAG_VERSION | QUICFLAG_CONNID_64bit | QUICFLAG_SEQNUM_8bit, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x04, 0x03, 0x02, 0x01, 0x0d},
		false, true, 0x01020304, 0x1122334455667788, 0x0d, true},

	// Tests[14-21] with various Sequence Number size and Version flags

	{[]byte{QUICFLAG_CONNID_0bit | QUICFLAG_SEQNUM_8bit, 0x0d},
		false, false, 0, 0, 0x0d, true},

	{[]byte{QUICFLAG_CONNID_0bit | QUICFLAG_SEQNUM_16bit, 0x0d, 0x0c},
		false, false, 0, 0, 0x0c0d, true},

	{[]byte{QUICFLAG_CONNID_0bit | QUICFLAG_SEQNUM_32bit, 0x0d, 0x0c, 0x0b, 0x0a},
		false, false, 0, 0, 0x0a0b0c0d, true},

	{[]byte{QUICFLAG_CONNID_0bit | QUICFLAG_SEQNUM_48bit, 0x0d, 0x0c, 0x0b, 0x0a, 0xdd, 0xcc},
		false, false, 0, 0, 0xccdd0a0b0c0d, true},

	{[]byte{QUICFLAG_VERSION | QUICFLAG_CONNID_0bit | QUICFLAG_SEQNUM_8bit, 0x04, 0x03, 0x02, 0x01, 0x0d},
		false, true, 0x01020304, 0, 0x0d, true},

	{[]byte{QUICFLAG_VERSION | QUICFLAG_CONNID_0bit | QUICFLAG_SEQNUM_16bit, 0x04, 0x03, 0x02, 0x01, 0x0d, 0x0c},
		false, true, 0x01020304, 0, 0x0c0d, true},

	{[]byte{QUICFLAG_VERSION | QUICFLAG_CONNID_0bit | QUICFLAG_SEQNUM_32bit, 0x04, 0x03, 0x02, 0x01, 0x0d, 0x0c, 0x0b, 0x0a},
		false, true, 0x01020304, 0, 0x0a0b0c0d, true},

	{[]byte{QUICFLAG_VERSION | QUICFLAG_CONNID_0bit | QUICFLAG_SEQNUM_48bit, 0x04, 0x03, 0x02, 0x01, 0x0d, 0x0c, 0x0b, 0x0a, 0xdd, 0xcc},
		false, true, 0x01020304, 0, 0xccdd0a0b0c0d, true},

	// Tests [22-26] with various Connection ID size, Sequence Number size and Version flags

	{[]byte{QUICFLAG_VERSION | QUICFLAG_CONNID_8bit | QUICFLAG_SEQNUM_16bit, 0x88, 0x04, 0x03, 0x02, 0x01, 0x0d, 0x0c},
		false, true, 0x01020304, 0x88, 0x0c0d, true},

	{[]byte{QUICFLAG_VERSION | QUICFLAG_CONNID_32bit | QUICFLAG_SEQNUM_16bit, 0x88, 0x77, 0x66, 0x55, 0x04, 0x03, 0x02, 0x01, 0x0d, 0x0c},
		false, true, 0x01020304, 0x55667788, 0x0c0d, true},

	{[]byte{QUICFLAG_VERSION | QUICFLAG_CONNID_32bit | QUICFLAG_SEQNUM_32bit, 0x88, 0x77, 0x66, 0x55, 0x04, 0x03, 0x02, 0x01, 0x0d, 0x0c, 0x0b, 0x0a},
		false, true, 0x01020304, 0x55667788, 0x0a0b0c0d, true},

	{[]byte{QUICFLAG_VERSION | QUICFLAG_CONNID_32bit | QUICFLAG_SEQNUM_48bit, 0x88, 0x77, 0x66, 0x55, 0x04, 0x03, 0x02, 0x01, 0x0d, 0x0c, 0x0b, 0x0a, 0xdd, 0xcc},
		false, true, 0x01020304, 0x55667788, 0xccdd0a0b0c0d, true},

	{[]byte{QUICFLAG_VERSION | QUICFLAG_CONNID_64bit | QUICFLAG_SEQNUM_48bit, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x04, 0x03, 0x02, 0x01, 0x0d, 0x0c, 0x0b, 0x0a, 0xdd, 0xcc},
		false, true, 0x01020304, 0x1122334455667788, 0xccdd0a0b0c0d, true},
}

func Test_QuicPublicHeader_ParseData(t *testing.T) {
	var pub QuicPublicHeader

	for i, v := range tests_quicpublicheader {
		s, err := pub.ParseData(v.data)
		if v.positifTest {
			if err != nil {
				t.Errorf("ParseData = error %s in test n°%v", err, i)
			}
			if s != len(v.data) {
				t.Errorf("ParseData = invalid parsed size in test n°%v with data[%v]%x", i, len(v.data), v.data)
			}
			if pub.GetPublicResetFlag() != v.flagPublicReset {
				t.Errorf("ParseData = invalid Public reset flag in test n°%v with data[%v]%x", i, len(v.data), v.data)
			}
			if pub.GetVersionFlag() != v.flagVersion {
				t.Errorf("ParseData = invalid Version flag in test n°%v with data[%v]%x", i, len(v.data), v.data)
			}
			if v.flagVersion {
				if pub.GetVersion() != v.version {
					t.Errorf("ParseData = invalid Version %x in test n°%v with data[%v]%x", pub.GetVersion(), i, len(v.data), v.data)
				}
			}
			if pub.GetConnectionID() != v.connId {
				t.Errorf("ParseData = invalid Connection ID %x in test n°%v with data[%v]%x", pub.GetConnectionID(), i, len(v.data), v.data)
			}
			if pub.GetSequenceNumber() != v.seqNum {
				t.Errorf("ParseData = invalid Sequence Number %x in test n°%v with data[%v]%x", pub.GetSequenceNumber(), i, len(v.data), v.data)
			}
		} else {
			if err == nil {
				t.Errorf("ParseData = missing error in test n°%v with data[%v]%x", i, len(v.data), v.data)
			}
		}
		pub.Erase()
	}
}

func Test_QuicPublicHeader_GetSerializedData(t *testing.T) {
	var pub QuicPublicHeader

	data := make([]byte, 19)
	for i, v := range tests_quicpublicheader {
		if v.positifTest {
			pub.SetPublicResetFlag(v.flagPublicReset)
			pub.SetVersionFlag(v.flagVersion)
			pub.SetVersion(v.version)
			pub.SetConnectionID(v.connId)
			pub.SetConnectionIdSize(parsePublicheaderConnectionIdSize[(v.data[0]>>2)&0x0f])
			pub.SetSequenceNumber(v.seqNum)
			pub.SetSequenceNumberSize(parsePublicheaderSequenceNumberSize[(v.data[0]>>2)&0x0f])
			s, err := pub.GetSerializedData(data)
			if err != nil {
				t.Errorf("GetSerializedData = error %s while serialized data in test n°%v", err, i)
			}
			if s != len(v.data) {
				t.Errorf("GetSerializedData = invalid serialized size in test n°%v with data[%v]%x", i, s, data[:s])
			}
			if !bytes.Equal(data[:s], v.data) {
				t.Errorf("GetSerializedData = invalid serialized data in test n°%v with data[%v]%x", i, s, data[:s])
			}
			pub.Erase()
		}
	}
}
