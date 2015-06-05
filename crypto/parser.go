// crypto package process crypto protocol messages and crypto handshake
package crypto

// internal Parser state's type.
type parserState uint32

// Constants use to describe current Parser's state.
const (
	sREADMESSAGETAG = iota
	sREADNUMBERENTRIES
	sREADTAGSANDOFFSETS
	sREADVALUES
)

// Parser is a crypto.Message parser that takes slices of bytes on its input channel and sends out crypto.Message(s) on its output channel.
//
// It handles the case where a crypto message is on multiple slices of bytes.
//
// When the Parser encounters a non valid crypto.Message a nil value is sends on its output channel.
type Parser struct {
	// input channel containing bytes to parse
	input chan []byte
	// output channel for sending parsed crypto.Message
	output chan *Message
	// internal Parser state variables that need to be keep when Parser is Start/Stop/Start/ ...
	state        parserState
	off          bool
	needMoreData uint32
	data         []byte
	msgTag       MessageTag
	numEntries   uint16
	tags         []MessageTag
	endOffsets   []uint32
	values       [][]byte
}

// NewParser is a crypto.Parser factory.
func NewParser() *Parser {
	return &Parser{
		input:        make(chan []byte),
		output:       make(chan *Message),
		state:        sREADMESSAGETAG,
		off:          true,
		needMoreDate: 4}
}

// GetInput returns the send only []byte input channel.
func (this *Parser) GetInput() chan<- []byte {
	return this.input
}

// GetOutput returns the receveive only crypto.Message output channel.
func (this *Parser) GetOutput() <-chan *Message {
	return this.output
}

// Stop method stops the Parser.
// The boolean value return is not an error and just in fact an indication about the state of the Parser before the call.
func (this *Parser) Stop() bool {
	if this.off {
		return false
	}
	this.off = true
	return true
}

// Start method starts the Parser if it is in 'Stop' state and return 'true', otherwise do nothing and return 'false'.
// The boolean value return is not an error and just in fact an indication about the state of the Parser before the call.
func (this *Parser) Start() bool {
	if this.off {
		this.off = false
		go this.runParser()
		return true
	}
	return false
}

// RunParser is the core function of the parsing process. It must only be launch as a Go routine by the Start function.
func (this *Parser) runParser() {
	var i, j int

	for {
		// Do we need to Stop parsing ?
		if this.off {
			return
		}

		// While not enough data in ringbuffer, append from input channel
		for this.needMoreData > uint32(len(this.data)) {
			this.data = append(this.data, <-this.input...)
		}

		// Read messages fields according to current Parser's state
		switch this.state {
		case sREADMESSAGETAG: // Read 4 bytes
			// Read uint32 message tag
			this.msgTag = MessageTag(this.data[0]) + MessageTag(this.data[1]>>8) + MessageTag(this.data[2]>>16) + MessageTag(this.data[3]>>24)
			// Advance reading slice of []byte
			this.data = this.data[4:]
			// Advance state
			this.state = sREADNUMBERENTRIES
			// Ask for next data size
			this.needMoreData = 4
			break
		case sREADNUMBERENTRIES: // Read 2+2 bytes
			// Read uint16 number of entries and ignore next uint16 of padding
			this.numEntries = uint16(this.data[0]) + (uint16(this.data[1]) << 8)
			if this.numEntries > MaxNumEntries {
				this.off = true
				this.output <- nil
			}
			// Advance reading slice of []byte
			this.data = this.data[4:]
			// Advance state
			this.state = sREADTAGSANDOFFSETS
			// Ask for next data size
			this.needMoreData = uint32(8 * this.numEntries)
			break
		case sREADTAGSANDOFFSETS: // Read numentries*(4+4)
			// Allocate ressources for tag-offset pairs
			this.tags = make([]MessageTag, this.numEntries)
			this.endOffsets = make([]uint32, this.numEntries)
			for i = 0; i < int(this.numEntries); i++ {
				j = i << 3
				// Read uint32 tag
				this.tags[i] = MessageTag(this.data[j]) + (MessageTag(this.data[j+1]) << 8) + (MessageTag(this.data[j+2]) << 16) + (MessageTag(this.data[j+3]) << 24)
				// Read uint32 offset
				this.endOffsets[i] = uint32(this.data[j]) + (uint32(this.data[j+1]) << 8) + (uint32(this.data[j+2]) << 16) + (uint32(this.data[j+3]) << 24)
			}
			// Advance reading slice of []byte
			this.data = this.data[this.numEntries*8:]
			// Advance state
			this.state = sREADVALUES
			// Ask for next data size
			this.needMoreData = this.endOffsets[this.numEntries-1]
			break
		case sREADVALUES:
			// Allocate ressources for tag-value pairs
			this.tags = make([]MessageTag, this.numEntries)
			// Read values
			j = 0
			for i = 0; i < int(this.numEntries); i++ {
				this.values[i] = this.data[j:this.endOffsets[i]]
				j = int(this.endOffsets[i])
			}
			// Advance reading slice of []byte
			this.data = this.data[this.endOffsets[this.numEntries-1]:]
			// Advance state
			this.state = sREADMESSAGETAG
			// Ask for next data size
			this.needMoreData = 4
			// Put Message on the output channel
			this.output <- &Message{
				msgTag: this.msgTag,
				tags:   this.tags,
				values: this.values}
			break
		}
	}
}
