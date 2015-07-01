package protocol

import "testing"
import "bytes"

type testquicfecpacket struct {
	positiveTest bool
	data         []byte
	seqnum       QuicPacketSequenceNumber
	offset       QuicFecGroupNumberOffset
}

var tests_quicfecpacket = []testquicfecpacket{
	{false, []byte{}, 0x0102030405060708, 0x42},
	{true, []byte{0x01}, 0x0102030405060708, 0x42},
	{true, []byte{0x01, 0x02}, 0x0102030405060708, 0x42},
	{true, []byte{0x01, 0x02, 0x03}, 0x0102030405060708, 0x42},
	{true, []byte{0x01, 0x02, 0x03, 0x04}, 0x0102030405060708, 0x42},
}

func Test_QuicFecPacket_ParseData(t *testing.T) {
	var fec QuicFECPacket

	for i, v := range tests_quicfecpacket {
		s, err := fec.ParseData(v.data)
		if v.positiveTest {
			if err != nil {
				t.Errorf("QuicFECPacket.ParseData : error %s in test %x with data[%v]%x", err, i, len(v.data), v.data)
			}
			if s != len(v.data) {
				t.Errorf("QuicFECPacket.ParseData : invalid size %v in test %x with data[%v]%x", s, i, len(v.data), v.data)
			}
			if !bytes.Equal(v.data, fec.redundancy) {
				t.Errorf("QuicFECPacket.ParseData : invalid redundancy data %x in test %x with data[%v]%x", fec.redundancy, i, len(v.data), v.data)
			}
		} else {
			if err == nil {
				t.Errorf("QuicFECPacket.ParseData : missing error in test %x with data[%v]%x", i, len(v.data), v.data)
			}
		}
	}
}

func Test_QuicFecPacket_GetSerializedData(t *testing.T) {
	var fec QuicFECPacket

	data := make([]byte, 4)
	for i, v := range tests_quicfecpacket {
		fec.Setup(v.seqnum, v.offset)
		fec.SetRedundancyData(v.data)
		s, err := fec.GetSerializedData(data)
		if v.positiveTest {
			if err != nil {
				t.Errorf("QuicFECPacket.GetSerializedData = error %s while serialized data in test n°%v", err, i)
			}
			if s != len(v.data) {
				t.Errorf("QuicFECPacket.GetSerializedData = invalid serialized size in test n°%v with data[%v]%x", i, s, data[:s])
			}
			if !bytes.Equal(data[:s], v.data) {
				t.Errorf("QuicFECPacket.GetSerializedData = invalid serialized data in test n°%v with data[%v]%x", i, s, data[:s])
			}
			if fec.seqNum != (v.seqnum - QuicPacketSequenceNumber(v.offset)) {
				t.Errorf("QuicFECPacket.GetSerializedData = invalid sequence number %x in test n°%v", fec.seqNum, i)
			}
			if fec.offset != v.offset {
				t.Errorf("QuicFECPacket.GetSerializedData = invalid FEC Group Number offset %x in test n°%v", fec.offset, i)
			}
		}
		fec.Erase()
	}

}
