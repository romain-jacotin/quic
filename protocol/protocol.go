package protocol

// DataParser interface
type DataParser interface {
	ParseData(data []byte) (size int, err error)
}

// DataSerializer interface
type DataSerialize interface {
	GetSerializedSize() int
	GetSerializedData(data []byte) (size int, err error)
}
