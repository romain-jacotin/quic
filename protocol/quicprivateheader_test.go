package protocol

import "testing"
import "bytes"

/*

     0       1
+--------+--------+
|Private | FEC (8)|
|Flags(8)|  (opt) |
+--------+--------+


Private flags:
+---+---+---+---+---+---+---+---+
| 0 | 0 | 0 | 0 | 0 |FEC|GRP|ENT|
+---+---+---+---+---+---+---+---+

*/

type testquicprivateheader struct {
	positiveTest  bool
	data          []byte
	flagFecPacket bool
	flagFecGroup  bool
	flagEntropy   bool
	offset        QuicFecGroupNumberOffset
}

var tests_quicprivateheader = []testquicprivateheader{
	// Test[0-2] invalid data size
	{false, []byte{}, true, true, true, 0x66},
	{false, []byte{0xf0}, false, false, false, 0x66},
	{false, []byte{0x07}, true, true, true, 0x66},
	// Test[3-6] various FEC Group and Entropy flags with FEC Packet flag set
	{true, []byte{QUICFLAG_FECPACKET | QUICFLAG_FECGROUP, 0x42}, true, true, false, 0x42},
	{false, []byte{QUICFLAG_FECPACKET | QUICFLAG_ENTROPY}, true, false, true, 0},
	{false, []byte{QUICFLAG_FECPACKET}, true, false, false, 0},
	{true, []byte{QUICFLAG_FECPACKET | QUICFLAG_FECGROUP | QUICFLAG_ENTROPY, 0x42}, true, true, true, 0x42},
	// Test[7-10] various FEC Group and Entropy flags with FEC Packet flag unset
	{true, []byte{QUICFLAG_FECGROUP | QUICFLAG_ENTROPY, 0x42}, false, true, true, 0x42},
	{true, []byte{QUICFLAG_FECGROUP, 0x42}, false, true, false, 0x42},
	{true, []byte{QUICFLAG_ENTROPY}, false, false, true, 0},
	{true, []byte{0}, false, false, false, 0},
}

func Test_QuicPrivateHeader_ParseData(t *testing.T) {
	var priv QuicPrivateHeader
	var fecgroupnum QuicFecGroupNumberOffset

	for i, v := range tests_quicprivateheader {
		s, err := priv.ParseData(v.data)
		if v.positiveTest {
			if err != nil {
				t.Errorf("ParseData = error %s in test n°%v", err, i)
			}
			if s != len(v.data) {
				t.Errorf("ParseData = invalid parsed size in test n°%v with data[%v]%x", i, len(v.data), v.data)
			}
			if priv.GetFecPacketFlag() != v.flagFecPacket {
				t.Errorf("ParseData = invalid FEC Packet flag in test n°%v with data[%v]%x", i, len(v.data), v.data)
			}
			if priv.GetFecGroupFlag() != v.flagFecGroup {
				t.Errorf("ParseData = invalid FEC Group presence flag in test n°%v with data[%v]%x", i, len(v.data), v.data)
			}
			if priv.GetEntropyFlag() != v.flagEntropy {
				t.Errorf("ParseData = invalid Entropy flag in test n°%v with data[%v]%x", i, len(v.data), v.data)
			}
			if v.flagFecGroup {
				if fecgroupnum, err = priv.GetFecGroupNumberOffset(); err != nil {
					t.Errorf("ParseData = error %s in test n°%v with data[%v]%x", err, i, len(v.data), v.data)
				}
				if fecgroupnum != v.offset {
					t.Errorf("ParseData = invalid FEC GRoup Offset value in test n°%v with data[%v]%x", i, len(v.data), v.data)
				}
			}
		} else {
			if err == nil {
				t.Errorf("ParseData = missing error in test n°%v with data[%v]%x", i, len(v.data), v.data)
			}
		}
		priv.Erase()
	}
}

func Test_QuicPrivateHeader_GetSerializedData(t *testing.T) {
	var priv QuicPrivateHeader

	data := make([]byte, 2)
	for i, v := range tests_quicprivateheader {
		if v.positiveTest {
			priv.SetEntropyFlag(v.flagEntropy)
			priv.SetFecGroupFlag(v.flagFecGroup)
			priv.SetFecPacketFlag(v.flagFecPacket)
			priv.SetFecGroupNumberOffset(v.offset)
			s, err := priv.GetSerializedData(data)
			if err != nil {
				t.Errorf("GetSerializedData = error %s while serialized data in test n°%v", err, i)
			}
			if s != len(v.data) {
				t.Errorf("GetSerializedData = invalid serialized size in test n°%v with data[%v]%x", i, s, data[:s])
			}
			if !bytes.Equal(data[:s], v.data) {
				t.Errorf("GetSerializedData = invalid serialized data in test n°%v with data[%v]%x", i, s, data[:s])
			}
			priv.Erase()
		}
	}
}
