package protocol

import "errors"
import "encoding/binary"

const (
	// Quic Frame type
	QUICFRAMETYPE_STREAM                   = 0x80
	QUICFRAMETYPE_STREAM_MASK              = 0x80
	QUICFRAMETYPE_ACK                      = 0x40
	QUICFRAMETYPE_ACK_MASK                 = 0xc0
	QUICFRAMETYPE_CONGESTION_FEEDBACK      = 0x20
	QUICFRAMETYPE_CONGESTION_FEEDBACK_MASK = 0xe0
	QUICFRAMETYPE_REGULAR_MASK             = 0x1f
	QUICFRAMETYPE_PADDING                  = 0x00
	QUICFRAMETYPE_RST_STREAM               = 0x01
	QUICFRAMETYPE_CONNECTION_CLOSE         = 0x02
	QUICFRAMETYPE_GOAWAY                   = 0x03
	QUICFRAMETYPE_WINDOW_UPDATE            = 0x04
	QUICFRAMETYPE_BLOCKED                  = 0x05
	QUICFRAMETYPE_STOP_WAITING             = 0x06
	QUICFRAMETYPE_PING                     = 0x07
)

type QuicFrameType byte
type QuicStreamID uint32
type QuicByteOffset uint64

type QuicFrame struct {
	frameType QuicFrameType
	// STREAM Frame fields
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
	// CONGESTION_FEEDBACK Frame fields
	// PADDING Frame fields
	paddingLength int
	// RST_STREAM Frame fields
	errorCode QuicErrorCode
	// CONNECTION_CLOSE Frame fields
	// GOAWAY Frame fields
	// WINDOW_UPDATE Frame fields = re-used of 'streamID' and 'byteOffset'
	// BLOCKED Frame fields
	// STOP_WAITING Frame fields
	// PING Frame fields
}

// Erase
func (this *QuicFrame) Erase() {
	this.frameType = 0
	// STREAM Frame fields
	this.flagFIN = false
	this.flagDataLength = false
	this.streamID = 0
	this.streamIDByteSize = 0
	this.byteOffset = 0
	this.byteOffsetByteSize = 0
	this.dataLength = 0
	this.data = nil
	// ACK Frame
	this.receivedEntropy = 0
	this.largestObserved = 0
	this.numTimestamp = 0
	this.numRanges = 0
	this.numRevived = 0
	// CONGESTION_FEEDBACK Frame fields
	// PADDING Frame fields
	this.paddingLength = 0
	// RST_STREAM Frame fields
	this.errorCode = 0
	// CONNECTION_CLOSE Frame fields
	// GOAWAY Frame fields
	// WINDOW_UPDATE Frame fields
	// BLOCKED Frame fields
	// STOP_WAITING Frame fields
	// PING Frame fields
}

// ParseData
func (this *QuicFrame) ParseData(data []byte) (size int, err error) {
	l := len(data)
	if l == 0 {
		err = errors.New("QuicFrame.ParseData : no data to parse")
		return
	}
	// Parse the frame type
	ft := data[0]
	if (ft & QUICFRAMETYPE_STREAM_MASK) == QUICFRAMETYPE_STREAM {
		// This is a STREAM Frame
		this.frameType = QUICFRAMETYPE_STREAM

	} else if (ft & QUICFRAMETYPE_ACK_MASK) == QUICFRAMETYPE_ACK {
		// This is an ACK Frame
		this.frameType = QUICFRAMETYPE_ACK

	} else if (ft & QUICFRAMETYPE_CONGESTION_FEEDBACK_MASK) == QUICFRAMETYPE_CONGESTION_FEEDBACK {
		// This is a CONGESTION_FEEDBACK Frame
		this.frameType = QUICFRAMETYPE_CONGESTION_FEEDBACK

	} else {
		switch ft {
		case 0x00: // PADDING Frame
			this.frameType = QUICFRAMETYPE_PADDING
			this.paddingLength = l - 1
			size = l
			return
		case 0x01: // RST_STREAM Frame
			this.frameType = QUICFRAMETYPE_RST_STREAM
			// Check data length
			if l < 17 {
				err = errors.New("QuicFrame.ParseData : not enough data (<17) for RST_STREAM Frame size")
				return
			}
			// Parse StreamId (32-bit)
			this.streamID = QuicStreamID(binary.LittleEndian.Uint32(data[1:]))
			// Parse Byte offset (64-bit)
			this.byteOffset = QuicByteOffset(binary.LittleEndian.Uint64(data[5:]))
			// Parse Error code
			this.errorCode = QuicErrorCode(binary.LittleEndian.Uint32(data[13:]))
			size = 17
			return
		case 0x02: // CONNECTION_CLOSE Frame
			this.frameType = QUICFRAMETYPE_CONNECTION_CLOSE
			err = errors.New("QuicFrame.ParseData : CONNECTION_CLOSE not yet implemented")
			return
		case 0x03: // GOAWAY Frame
			this.frameType = QUICFRAMETYPE_GOAWAY
			err = errors.New("QuicFrame.ParseData : GOAWAY not yet implemented")
			return
		case 0x04: // WINDOW_UPDATE Frame
			this.frameType = QUICFRAMETYPE_WINDOW_UPDATE
			// Check data length
			if l < 13 {
				err = errors.New("QuicFrame.ParseData : not enough data (<13) for WINDOW_UPDATE Frame size")
				return
			}
			// Parse StreamId (32-bit)
			this.streamID = QuicStreamID(binary.LittleEndian.Uint32(data[1:]))
			// Parse Byte offset (64-bit)
			this.byteOffset = QuicByteOffset(binary.LittleEndian.Uint64(data[5:]))
			size = 13
			return
		case 0x05: // BLOCKED Frame
			this.frameType = QUICFRAMETYPE_BLOCKED
			// Check data length
			if l < 5 {
				err = errors.New("QuicFrame.ParseData : not enough data (<5) for BLOCKED Frame size")
				return
			}
			// Parse StreamId (32-bit)
			this.streamID = QuicStreamID(binary.LittleEndian.Uint32(data[1:]))
			size = 5
			return
		case 0x06: // STOP_WAITING Frame
			this.frameType = QUICFRAMETYPE_STOP_WAITING
			err = errors.New("QuicFrame.ParseData : STOP_WAITING not yet implemented")
			return
		case 0x07: // PING Frame
			this.frameType = QUICFRAMETYPE_PING
			size = 1
			return
		default:
			err = errors.New("QuicFrame.ParseData : unknown frame type")
		}
	}
	return
}

// GetSerializedSize
func (this *QuicFrame) GetSerializedSize() (size int) {
	switch this.frameType {
	case QUICFRAMETYPE_STREAM: // variable length
		return
	case QUICFRAMETYPE_ACK: // variable length
		return
	case QUICFRAMETYPE_CONGESTION_FEEDBACK: // unknow length ...
		return
	case QUICFRAMETYPE_PADDING: // variable length
		size = this.paddingLength
		return
	case QUICFRAMETYPE_RST_STREAM: // fix length (17 bytes)
		size = 17
		return
	case QUICFRAMETYPE_CONNECTION_CLOSE: // variable length
		return
	case QUICFRAMETYPE_GOAWAY: // variable length
		return
	case QUICFRAMETYPE_WINDOW_UPDATE: // fix length (13 bytes)
		size = 13
		return
	case QUICFRAMETYPE_BLOCKED: // fix length (5 bytes)
		size = 5
		return
	case QUICFRAMETYPE_STOP_WAITING: // 3 <= variable length <= 8
		return
	case QUICFRAMETYPE_PING: // fix length (1 byte)
		size = 1
		return
	}
	return
}

// GetSerializedData
func (this *QuicFrame) GetSerializedData(data []byte) (size int, err error) {
	switch this.frameType {
	case QUICFRAMETYPE_STREAM: // variable length
		// Serialize frame type
		data[0] = QUICFRAMETYPE_STREAM
		err = errors.New("NOT YET IMPLEMENTED !")
		return
	case QUICFRAMETYPE_ACK: // variable length
		// Serialize frame type
		data[0] = QUICFRAMETYPE_ACK
		err = errors.New("NOT YET IMPLEMENTED !")
		return
	case QUICFRAMETYPE_CONGESTION_FEEDBACK: // unknow length ...
		// Serialize frame type
		data[0] = QUICFRAMETYPE_CONGESTION_FEEDBACK
		err = errors.New("NOT YET IMPLEMENTED !")
		return
	case QUICFRAMETYPE_PADDING: // variable length
		// Serialize frame type
		data[0] = QUICFRAMETYPE_PADDING
		// Serialize padding length of zeros
		size = this.paddingLength
		for i := range data[:size] {
			data[i] = 0
		}
		return
	case QUICFRAMETYPE_RST_STREAM: // fix length (17 bytes)
		size = 17
		if len(data) < size {
			size = 0
			err = errors.New("QuicFrame.GetSerializedData : data size too small to contain RST_STREAM Frame (<17)")
			return
		}
		// Serialize frame type
		data[0] = QUICFRAMETYPE_RST_STREAM
		// Serialize Stream ID
		binary.LittleEndian.PutUint32(data[1:], uint32(this.streamID))
		// Serialize Byte offset
		binary.LittleEndian.PutUint64(data[5:], uint64(this.byteOffset))
		// Serialize Error code
		binary.LittleEndian.PutUint32(data[13:], uint32(this.errorCode))
		return
	case QUICFRAMETYPE_CONNECTION_CLOSE: // variable length
		// Serialize frame type
		data[0] = QUICFRAMETYPE_CONNECTION_CLOSE
		err = errors.New("NOT YET IMPLEMENTED !")
		return
	case QUICFRAMETYPE_GOAWAY: // variable length
		// Serialize frame type
		data[0] = QUICFRAMETYPE_GOAWAY
		err = errors.New("NOT YET IMPLEMENTED !")
		return
	case QUICFRAMETYPE_WINDOW_UPDATE: // fix length (13 bytes)
		size = 13
		if len(data) < size {
			size = 0
			err = errors.New("QuicFrame.GetSerializedData : data size too small to contain WINDOW_UPDATE Frame (<13)")
			return
		}
		// Serialize frame type
		data[0] = QUICFRAMETYPE_WINDOW_UPDATE
		// Serialize Stream ID
		binary.LittleEndian.PutUint32(data[1:], uint32(this.streamID))
		// Serialize Byte offset
		binary.LittleEndian.PutUint64(data[5:], uint64(this.byteOffset))
		return
	case QUICFRAMETYPE_BLOCKED: // fix length (5 bytes)
		size = 5
		if len(data) < size {
			size = 0
			err = errors.New("QuicFrame.GetSerializedData : data size too small to contain BLOCKED Frame (<5)")
			return
		}
		// Serialize frame type
		data[0] = QUICFRAMETYPE_BLOCKED
		// Serialize Stream ID
		binary.LittleEndian.PutUint32(data[1:], uint32(this.streamID))
		return
	case QUICFRAMETYPE_STOP_WAITING: // 3 <= variable length <= 8
		// Serialize frame type
		data[0] = QUICFRAMETYPE_STOP_WAITING
		err = errors.New("NOT YET IMPLEMENTED !")
		return
	case QUICFRAMETYPE_PING: // fix length (1 byte)
		// Check minimum data size
		size = 1
		if len(data) < size {
			size = 0
			err = errors.New("QuicFrame.GetSerializedData : data size too small to contain PING Frame (<1)")
			return
		}
		// Serialized frame type
		data[0] = QUICFRAMETYPE_PING
		return
	}
	return
}

// SetFrameType
func (this *QuicFrame) SetFrameType(frameType QuicFrameType) {
	this.frameType = frameType
}

// GetFrameType
func (this *QuicFrame) GetFrameType() QuicFrameType {
	return this.frameType
}
