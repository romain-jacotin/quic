package protocol

import "errors"

const (
	// Quic Frame type
	QUICFRAMETYPE_STREAM = iota
	QUICFRAMETYPE_ACK
	QUICFRAMETYPE_CONGESTION_FEEDBACK
	QUICFRAMETYPE_PADDING
	QUICFRAMETYPE_RST_STREAM
	QUICFRAMETYPE_CONNECTION_CLOSE
	QUICFRAMETYPE_GOAWAY
	QUICFRAMETYPE_WINDOW_UPDATE
	QUICFRAMETYPE_BLOCKED
	QUICFRAMETYPE_STOP_WAITING
	QUICFRAMETYPE_PING
)

type QuicFrameType byte
type QuicStreamID uint32
type QuicByteOffset uint64

type QuicFrame struct {
	frameType QuicFrameType
	// STREAM Frame
	flagFIN            bool
	flagDataLength     bool
	streamID           QuicStreamID
	streamIDByteSize   int
	byteOffset         QuicByteOffset
	byteOffsetByteSize int
	dataLength         uint32
	data               []byte
	// ACK Frame
	receivedEntropy byte
	largestObserved QuicPacketSequenceNumber
	numTimestamp    byte
	numRanges       byte
	numRevived      byte
}

// ParseData
func (this *QuicFrame) ParseData(data []byte) (size int, err error) {
	// Parse the frame type
	ft := data[0]
	if (ft & 0x80) == 0x80 {
		// This is a STREAM Frame
		this.frameType = QUICFRAMETYPE_STREAM

	} else if (ft & 0x40) == 0x40 {
		// This is an ACK Frame
		this.frameType = QUICFRAMETYPE_ACK

	} else if (ft & 0x20) == 0x20 {
		// This is a CONGESTION_FEEDBACK Frame
		this.frameType = QUICFRAMETYPE_CONGESTION_FEEDBACK

	} else {
		switch ft {
		case 0x00: // PADDING Frame
			this.frameType = QUICFRAMETYPE_PADDING
			size = len(data)
			return
		case 0x01: // RST_STREAM Frame
			this.frameType = QUICFRAMETYPE_RST_STREAM
			size++
			return
		case 0x02: // CONNECTION_CLOSE Frame
			this.frameType = QUICFRAMETYPE_CONNECTION_CLOSE
			size++
			return
		case 0x03: // GOAWAY Frame
			this.frameType = QUICFRAMETYPE_GOAWAY
			size++
			return
		case 0x04: // WINDOW_UPDATE Frame
			this.frameType = QUICFRAMETYPE_WINDOW_UPDATE
			size++
			return
		case 0x05: // BLOCKED Frame
			this.frameType = QUICFRAMETYPE_BLOCKED
			size++
			return
		case 0x06: // STOP_WAITING Frame
			this.frameType = QUICFRAMETYPE_STOP_WAITING
			size++
			return
		case 0x07: // PING Frame
			this.frameType = QUICFRAMETYPE_PING
			size++
			return
		default:
			err = errors.New("QuicFrame.ParseData : unknown frame type")
		}
	}
	return
}

// GetSerializedSize
func (this *QuicFrame) GetSerializedSize() (size int) {
	return
}

// GetSerializedData
func (this *QuicFrame) GetSerializedData(data []byte) (size int, err error) {
	err = errors.New("NOT YET IMPLEMENTED !")
	return
}

// GetFrameType
func (this *QuicFrame) GetFrameType() QuicFrameType {
	return this.GetFrameType()
}
