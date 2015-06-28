package protocol

import "testing"
import "bytes"

func Test_NewMessage(t *testing.T) {
	var msg *Message

	if msg = NewMessage(TagCHLO); msg == nil {
		t.Error("NewMessage: return nil on CHLO")
	}
	if msg.GetMessageTag() != TagCHLO {
		t.Error("NewMessage: invalid new CHLO message")
	}
	if msg = NewMessage(TagREJ); msg == nil {
		t.Error("NewMessage: return nil on REJ")
	}
	if msg.GetMessageTag() != TagREJ {
		t.Error("NewMessage: invalid new REJ message")
	}
	if msg = NewMessage(TagSHLO); msg == nil {
		t.Error("NewMessage: return nil on SHLO")
	}
	if msg.GetMessageTag() != TagSHLO {
		t.Error("NewMessage: invalid new SHLO message")
	}
	if msg = NewMessage(TagSCUP); msg == nil {
		t.Error("NewMessage: return nil on SCUP")
	}
	if msg.GetMessageTag() != TagSCUP {
		t.Error("NewMessage: invalid new SCUP message")
	}
	if msg = NewMessage(666); msg != nil {
		t.Error("NewMessage: not returning nil on bad message tag")
	}
	msg = NewMessage(TagCHLO)
	msg.AddTagValue(TagSTK, []byte{0, 1})

	if msg.GetMessageTag() != TagCHLO {
		t.Error("NewMessage: bad message tag initialization")
	}
	if msg.GetNumEntries() != 1 {
		t.Error("NewMessage: bad tag/value pairs initialization")
	}
	if b, v := msg.ContainsTag(TagSTK); !b {
		t.Error("NewMessage: bad tag/value pairs initialization")
	} else if !bytes.Equal(v, []byte{0, 1}) {
		t.Error("NewMessage: bad tag/value pairs initialization")
	}
}

func Test_GetMessageTag(t *testing.T) {
	msg := NewMessage(TagCHLO)
	if msg.GetMessageTag() != TagCHLO {
		t.Error("GetMessageTag: bad message tag")
	}
}

func Test_IsMessageTag(t *testing.T) {
	msg := NewMessage(TagSCUP)
	if msg.IsMessageTag(TagCHLO) {
		t.Error("IsMessageTag: bad message tag")
	}
	if !msg.IsMessageTag(TagSCUP) {
		t.Error("IsMessageTag: bad message tag")
	}
}

func Test_GetNumEntries(t *testing.T) {
	msg := NewMessage(TagREJ)
	if msg.GetNumEntries() != 0 {
		t.Error("GetNumEntries: bad value, must be zero")
	}
	msg = NewMessage(TagSHLO)
	msg.AddTagValue(TagAEAD, []byte{0, 1})
	msg.AddTagValue(TagCETV, []byte{2, 3})
	if msg.GetNumEntries() != 2 {
		t.Error("GetNumEntries: bad value, must be 2")
	}
}

func Test_ContainsTag(t *testing.T) {
	var b bool
	var v []byte

	msg := NewMessage(TagREJ)
	if b, v = msg.ContainsTag(TagCETV); b {
		t.Error("ContainsTag: tag can't be in the Message")
	}
	msg = NewMessage(TagSHLO)
	msg.AddTagValue(TagAEAD, []byte{0, 1})
	msg.AddTagValue(TagCETV, []byte{2, 3})
	msg.AddTagValue(TagSCFG, []byte{4, 5})
	if b, v = msg.ContainsTag(TagKEXS); b {
		t.Error("ContainsTag: tag can't be in the Message")
	}
	if v != nil {
		t.Error("ContainsTag: unknow tag can't have a value in the Message")
	}
	if b, v = msg.ContainsTag(TagAEAD); !b {
		t.Error("ContainsTag: tag must be in the Message")
	}
	if !bytes.Equal(v, []byte{0, 1}) {
		t.Error("ContainsTag: invalid associated value for this tag")
	}
	if b, v = msg.ContainsTag(TagCETV); !b {
		t.Error("ContainsTag: tag must be in the Message")
	}
	if !bytes.Equal(v, []byte{2, 3}) {
		t.Error("ContainsTag: invalid associated value for this tag")
	}
	if b, v = msg.ContainsTag(TagSCFG); !b {
		t.Error("ContainsTag: tag must be in the Message")
	}
	if !bytes.Equal(v, []byte{4, 5}) {
		t.Error("ContainsTag: invalid associated value for this tag")
	}
}

func Test_UpdateTagValue(t *testing.T) {
	var b bool
	var v []byte

	msg := NewMessage(TagSHLO)
	msg.AddTagValue(TagAEAD, []byte{0, 1})
	msg.AddTagValue(TagCETV, []byte{2, 3})
	msg.AddTagValue(TagSCFG, []byte{4, 5})
	if msg.UpdateTagValue(TagKEXS, []byte{6, 7}) {
		t.Error("UpdateTagValue: can update a tag value that is not already exist")
	}
	if !msg.UpdateTagValue(TagAEAD, []byte{8, 9}) {
		t.Error("UpdateTagValue: can't update a tag value that is already exist")
	}
	if b, v = msg.ContainsTag(TagAEAD); !b {
		t.Error("UpdateTagValue: can't update a tag value that is already exist")
	}
	if !bytes.Equal(v, []byte{8, 9}) {
		t.Error("UpdateTagValue: can't update a tag value that is already exist")
	}
	if !msg.UpdateTagValue(TagCETV, []byte{10, 11}) {
		t.Error("UpdateTagValue: can't update a tag value that is already exist")
	}
	if b, v = msg.ContainsTag(TagCETV); !b {
		t.Error("UpdateTagValue: can't update a tag value that is already exist")
	}
	if !bytes.Equal(v, []byte{10, 11}) {
		t.Error("UpdateTagValue: can't update a tag value that is already exist")
	}
	if !msg.UpdateTagValue(TagSCFG, []byte{12, 13}) {
		t.Error("UpdateTagValue: can't update a tag value that is already exist")
	}
	if b, v = msg.ContainsTag(TagSCFG); !b {
		t.Error("UpdateTagValue: can't update a tag value that is already exist")
	}
	if !bytes.Equal(v, []byte{12, 13}) {
		t.Error("UpdateTagValue: can't update a tag value that is already exist")
	}
}

func Test_AddTagValue(t *testing.T) {
	var b bool
	var v []byte

	msg := NewMessage(TagREJ)
	msg.AddTagValue(TagAESG, []byte{0, 1})
	if msg.GetNumEntries() != 1 {
		t.Error("AddTagValue: invalid number of entries")
	}
	if b, v = msg.ContainsTag(TagAESG); !b {
		t.Error("AddTagValue: can'f find added tag")
	}
	if !bytes.Equal(v, []byte{0, 1}) {
		t.Error("AddTagValue: can'f find added tag/value")
	}
	msg.AddTagValue(TagSCFG, []byte{2, 3})
	if msg.GetNumEntries() != 2 {
		t.Error("AddTagValue: invalid number of entries")
	}
	if b, v = msg.ContainsTag(TagSCFG); !b {
		t.Error("AddTagValue: can'f find added tag")
	}
	if !bytes.Equal(v, []byte{2, 3}) {
		t.Error("AddTagValue: can'f find added tag/value")
	}
	msg.AddTagValue(TagKEXS, []byte{4, 5})
	if msg.GetNumEntries() != 3 {
		t.Error("AddTagValue: invalid number of entries")
	}
	if b, v = msg.ContainsTag(TagKEXS); !b {
		t.Error("AddTagValue: can'f find added tag")
	}
	if !bytes.Equal(v, []byte{4, 5}) {
		t.Error("AddTagValue: can'f find added tag/value")
	}
	msg.AddTagValue(TagAEAD, []byte{6, 7})
	if msg.GetNumEntries() != 4 {
		t.Error("AddTagValue: invalid number of entries")
	}
	if b, v = msg.ContainsTag(TagAEAD); !b {
		t.Error("AddTagValue: can'f find added tag")
	}
	if !bytes.Equal(v, []byte{6, 7}) {
		t.Error("AddTagValue: can'f find added tag/value")
	}
}

func Test_GetSerializeSize(t *testing.T) {
	msg := NewMessage(TagCHLO)
	if msg.GetSerializeSize() != 8 {
		t.Error("GetSerializeSize: bad size")
	}
	msg.AddTagValue(TagSNI, []byte{1})
	if msg.GetSerializeSize() != (8 + 1*8 + 1) {
		t.Error("GetSerializeSize: bad size")
	}
	msg.AddTagValue(TagCETV, []byte{2, 3})
	if msg.GetSerializeSize() != (8 + 2*8 + 3) {
		t.Error("GetSerializeSize: bad size")
	}
	msg.AddTagValue(TagAEAD, []byte{4, 5, 6})
	if msg.GetSerializeSize() != (8 + 3*8 + 6) {
		t.Error("GetSerializeSize: bad size")
	}
}

func Test_GetSerialize(t *testing.T) {
	msg := NewMessage(TagCHLO)
	s := msg.GetSerialize()
	r := []byte{'C', 'H', 'L', 'O', 0, 0, 0, 0}
	if !bytes.Equal(s, r) {
		t.Error("GetSerialize: bad binary string")
	}

	msg.AddTagValue(TagSNI, []byte{1})
	s = msg.GetSerialize()
	r = []byte{'C', 'H', 'L', 'O', 1, 0, 0, 0, 'S', 'N', 'I', 0, 1, 0, 0, 0, 1}
	if !bytes.Equal(s, r) {
		t.Error("GetSerialize: bad binary string")
	}

	msg.AddTagValue(TagCETV, []byte{2, 3})
	s = msg.GetSerialize()
	r = []byte{'C', 'H', 'L', 'O', 2, 0, 0, 0, 'S', 'N', 'I', 0, 1, 0, 0, 0, 'C', 'E', 'T', 'V', 3, 0, 0, 0, 1, 2, 3}
	if !bytes.Equal(s, r) {
		t.Error("GetSerialize: bad binary string")
	}

	msg.AddTagValue(TagAEAD, []byte{4, 5, 6})
	s = msg.GetSerialize()
	r = []byte{'C', 'H', 'L', 'O', 3, 0, 0, 0, 'S', 'N', 'I', 0, 1, 0, 0, 0, 'A', 'E', 'A', 'D', 4, 0, 0, 0, 'C', 'E', 'T', 'V', 6, 0, 0, 0, 1, 4, 5, 6, 2, 3}
	if !bytes.Equal(s, r) {
		t.Error("GetSerialize: bad binary string")
	}
}
