package Neo

const (
	SCRIPT_HASH_LENGTH 	byte = 20
	NEO_ADDRESS_VERSION 	byte = 0x17
	NEO_PRIVATE_VERSION	byte = 0x80
	NEO_PRIVATE_SENTINEL byte = 0x01
)

type Address struct {
	Addr string
	Script []byte
}

func (addr *Address) GetAddr() string  {
	return addr.Addr
}

