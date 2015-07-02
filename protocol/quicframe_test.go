package protocol

import "testing"

type testquicframe struct {
	positiveTest       bool
	data               []byte
	frameType          QuicFrameType
	flagFIN            bool
	flagDataLength     bool
	streamID           QuicStreamID
	streamIDByteSize   int
	byteOffset         QuicByteOffset
	byteOffsetByteSize int
	frameLength        uint32
	frameData          []byte
}

/*
var tests_quicframe = []testquicframe{
	{false, []byte{},
	QUICFRAMETYPE_PADDING, // frame type
	false,
	},
}
*/

func Test_QuicFrame_ParseData(t *testing.T) {

}

func Test_QuicFrame_GetSerializedData(t *testing.T) {

}
