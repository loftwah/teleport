package protocol

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"unicode/utf16"

	"github.com/gravitational/trace"
)

type Login7Packet struct {
	Packet Packet

	Length        uint32
	TDSVersion    uint32
	PacketSize    uint32
	ClientProgVer uint32
	ClientPID     uint32
	ConnectionID  uint32
}

func ReadLogin7Packet(conn net.Conn) (*Login7Packet, error) {
	pkt, err := ReadPacket(conn)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if pkt.Type != PacketTypeLogin7 {
		return nil, trace.BadParameter("expected LOGIN7 packet, got: %#v", pkt)
	}
	return &Login7Packet{
		Packet: *pkt,
		// Length:        binary.BigEndian.Uint32(pkt.Data[0:4]),
		// TDSVersion:    binary.BigEndian.Uint32(pkt.Data[4:8]),
		// PacketSize:    binary.BigEndian.Uint32(pkt.Data[8:12]),
		// ClientProgVer: binary.BigEndian.Uint32(pkt.Data[12:16]),
		// ClientPID:     binary.BigEndian.Uint32(pkt.Data[16:20]),
		// ConnectionID:  binary.BigEndian.Uint32(pkt.Data[20:24]),
	}, nil
}

func WriteLogin7Response(conn net.Conn) error {
	login7 := &Login7Response{
		Tokens: []Token{
			&LoginAckToken{
				Interface:  1,
				TDSVersion: verTDS74,
				ProgName:   "Teleport",
				ProgVer:    0,
			},
			&DoneToken{},
		},
	}

	data, err := login7.Tokens.Marshal()
	if err != nil {
		return trace.Wrap(err)
	}

	header := []byte{
		PacketTypeResponse, // type
		0x1,                // status - mark as last
		0, 0,               // length
		0, 0,
		0, // packet ID
		0,
	}

	// Update packet length.
	binary.BigEndian.PutUint16(header[2:], uint16(len(data)+8))

	pkt := append(header, data...)

	fmt.Println("=== SENT LOGIN7 PACKET ===")
	fmt.Println(hex.Dump(pkt))
	fmt.Println("=======================")

	// Write packet to connection.
	_, err = conn.Write(pkt)
	if err != nil {
		return trace.Wrap(err)
	}

	return nil
}

type Login7Response struct {
	PacketHeader
	Tokens Tokens
}

type Tokens []Token

func (t Tokens) Marshal() ([]byte, error) {
	var b []byte
	for _, tt := range t {
		bb, err := tt.Marshal()
		if err != nil {
			return nil, trace.Wrap(err)
		}
		b = append(b, bb...)
	}
	return b, nil
}

type Token interface {
	Marshal() ([]byte, error)
}

type LoginAckToken struct {
	Interface  uint8
	TDSVersion uint32
	ProgName   string
	ProgVer    uint32
}

func (t *LoginAckToken) Marshal() ([]byte, error) {
	length := 1 + 4 + len(t.ProgName)*2 + 4

	// Type + length + data.
	b := bytes.NewBuffer(make([]byte, 0, 1+2+length))

	// Token type.
	b.WriteByte(loginAckTokenType)

	// Token length.
	binary.Write(b, binary.LittleEndian, uint16(length))

	// Interface.
	b.WriteByte(t.Interface)

	// TDS version.
	binary.Write(b, binary.BigEndian, t.TDSVersion)

	// Program name.
	progName := str2ucs2(t.ProgName)
	binary.Write(b, binary.LittleEndian, uint8(len(progName)/2))
	b.Write(progName)

	// Program version.
	binary.Write(b, binary.LittleEndian, t.ProgVer)

	bytes := b.Bytes()

	fmt.Printf("--> Marshaled LoginAck token: %#v\n", bytes)

	return bytes, nil
}

type DoneToken struct {
	Status   uint16
	CurCmd   uint16
	RowCount uint64
}

func (t *DoneToken) Marshal() ([]byte, error) {
	b := bytes.NewBuffer(make([]byte, 0, 1+2+2+8))

	// Token type.
	b.WriteByte(doneTokenType)

	// Status.
	binary.Write(b, binary.LittleEndian, t.Status)

	// Current command.
	binary.Write(b, binary.LittleEndian, t.CurCmd)

	// Row count.
	binary.Write(b, binary.LittleEndian, t.RowCount)

	bytes := b.Bytes()

	fmt.Printf("--> Marshaled Done token: %#v\n", bytes)

	return bytes, nil
}

const (
	loginAckTokenType uint8 = 0xAD
	doneTokenType     uint8 = 0xFD
)

// convert Go string to UTF-16 encoded []byte (littleEndian)
// done manually rather than using bytes and binary packages
// for performance reasons
func str2ucs2(s string) []byte {
	res := utf16.Encode([]rune(s))
	ucs2 := make([]byte, 2*len(res))
	for i := 0; i < len(res); i++ {
		ucs2[2*i] = byte(res[i])
		ucs2[2*i+1] = byte(res[i] >> 8)
	}
	return ucs2
}
