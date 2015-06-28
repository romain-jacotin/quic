package protocol

import "testing"
import "bytes"

func tests(in chan<- []byte) {
	in <- []byte{'C', 'H', 'L', 'O', 0, 0, 0, 0}
	in <- []byte{'C', 'H', 'L', 'O', 1, 0, 0, 0, 'S', 'N', 'I', 0, 1, 0, 0, 0, 1}
	in <- []byte{'C', 'H', 'L', 'O', 2, 0, 0, 0, 'S', 'N', 'I', 0, 1, 0, 0, 0, 'C', 'E', 'T', 'V', 3, 0, 0, 0, 1, 2, 3}
	in <- []byte{'C', 'H', 'L', 'O', 3, 0, 0, 0, 'S', 'N', 'I', 0, 1, 0, 0, 0, 'A', 'E', 'A', 'D', 4, 0, 0, 0, 'C', 'E', 'T', 'V', 6, 0, 0, 0, 1, 4, 5, 6, 2, 3}
}

func Test_Parser(t *testing.T) {
	var b bool
	var v []byte

	parser := NewParser()
	go tests(parser.GetInput())
	parser.Start()
	out := parser.GetOutput()

	msg := <-out
	if msg.GetMessageTag() != TagCHLO {
		t.Error("Parser: invalid message tag")
	}
	if msg.GetNumEntries() != 0 {
		t.Error("Parser: invalid number of tag/value entries")
	}

	msg = <-out
	if msg.GetMessageTag() != TagCHLO {
		t.Error("Parser: invalid message tag")
	}
	if msg.GetNumEntries() != 1 {
		t.Error("Parser: invalid number of tag/value entries")
	}
	if b, v = msg.ContainsTag(TagSNI); !b {
		t.Error("Parser: tag is not exist in the Message")
	}
	if !bytes.Equal(v, []byte{1}) {
		t.Error("Parser: invalid tag value")
	}

	msg = <-out
	if msg.GetMessageTag() != TagCHLO {
		t.Error("Parser: invalid message tag")
	}
	if msg.GetNumEntries() != 2 {
		t.Error("Parser: invalid number of tag/value entries")
	}
	if b, v = msg.ContainsTag(TagSNI); !b {
		t.Error("Parser: tag is not exist in the Message")
	}
	if !bytes.Equal(v, []byte{1}) {
		t.Error("Parser: invalid tag value")
	}
	if b, v = msg.ContainsTag(TagCETV); !b {
		t.Error("Parser: tag is not exist in the Message")
	}
	if !bytes.Equal(v, []byte{2, 3}) {
		t.Error("Parser: invalid tag value")
	}

	msg = <-out
	if msg.GetMessageTag() != TagCHLO {
		t.Error("Parser: invalid message tag")
	}
	if msg.GetNumEntries() != 3 {
		t.Error("Parser: invalid number of tag/value entries")
	}
	if b, v = msg.ContainsTag(TagSNI); !b {
		t.Error("Parser: tag is not exist in the Message")
	}
	if !bytes.Equal(v, []byte{1}) {
		t.Error("Parser: invalid tag value")
	}
	if b, v = msg.ContainsTag(TagCETV); !b {
		t.Error("Parser: tag is not exist in the Message")
	}
	if !bytes.Equal(v, []byte{2, 3}) {
		t.Error("Parser: invalid tag value")
	}
	if b, v = msg.ContainsTag(TagAEAD); !b {
		t.Error("Parser: tag is not exist in the Message")
	}
	if !bytes.Equal(v, []byte{4, 5, 6}) {
		t.Error("Parser: invalid tag value")
	}
	parser.Stop()
}
