package protocol

import "errors"

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

    13      14       15        16        17       18       19       20
+--------+--------+--------+--------+--------+--------+--------+--------+
|         Sequence Number (8, 16, 32, or 48)          |Private | FEC (8)|
|                         (variable length)           |Flags(8)|  (opt) |
+--------+--------+--------+--------+--------+--------+--------+--------+

*/

// QuicPrivateHeader
type QuicPrivateHeader struct {
	flagFec bool
}

// ParseData
func (this *QuicPrivateHeader) ParseData(data []byte) (size int, err error) {
	err = errors.New("NOT YET IMPLEMENTED !")
	return
}

// GetSerializedSize
func (this *QuicPrivateHeader) GetSerializedSize() (size int) {
	return
}

// GetSerializedData
func (this *QuicPrivateHeader) GetSerializedData(data []byte) (size int, err error) {
	err = errors.New("NOT YET IMPLEMENTED !")
	return
}

// GetFecFlag
func (this *QuicPrivateHeader) GetFecFlag() bool {
	return this.flagFec
}

// SetFecFlag
func (this *QuicPrivateHeader) SetFecFlag(fecFlag bool) {
	this.flagFec = fecFlag
	return
}
