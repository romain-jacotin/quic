package crypto

type parserState uint32

// Constants use to describe current Parser's state
const (
	sREADMESSAGETAG = iota
	sREADNUMBERENTRIES
	sREADTAGSANDOFFSETS
	sREADVALUES
)

// Parser is
type Parser struct {
	input  chan []byte
	output chan *Message
	state  parserState
	off    bool
}

// NewParser is a crypto.Parser factory
func (*Parser) NewParser() *Parser {
	p := new(Parser)
	p.input = make(chan []byte)
	p.output = make(chan *Message)
	p.state = sREADMESSAGETAG
	p.off = true
	return p
}

// GetInput returns the send only []byte channel
func (this *Parser) GetInput() chan<- []byte {
	return this.input
}

// GetOutput returns the receveive only crypto.Message channel
func (this *Parser) GetOutput() <-chan *Message {
	return this.output
}

// Stop method stops the Parser
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

// RunParser is the core function of the parsing process. It must be launch as a Go routine by the Parser factory.
func (this *Parser) runParser() {
	for {
		// Do we need to Stop parsing ?
		if this.off {
			return
		}

		// Read messages fields according to current Parser's state
		switch this.state {
		case sREADMESSAGETAG:
			break
		case sREADNUMBERENTRIES:
			break
		case sREADTAGSANDOFFSETS:
			break
		case sREADVALUES:
			break
		}

		// Append buffer if pending byte[] in input channel
	}
}
