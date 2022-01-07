package protocol

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sort"

	"github.com/gravitational/trace"
)

type PreloginPacket struct {
	Packet Packet
}

func ReadPreloginPacket(conn net.Conn) (*PreloginPacket, error) {
	pkt, err := ReadPacket(conn)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if pkt.Type != PacketTypePreLogin {
		return nil, trace.BadParameter("expected PRELOGIN packet, got: %#v", pkt)
	}
	return &PreloginPacket{
		Packet: *pkt,
	}, nil
}

func WritePreloginResponse(conn net.Conn) error {
	var err error

	w := bytes.NewBuffer([]byte{
		PacketTypePreLogin, // type
		0x01,               // status - mark as last
		0, 0,               // length
		0, 0,
		0,
		0,
	})

	fields := map[uint8][]byte{
		preloginVERSION:    {0, 0, 0, 0, 0, 0},
		preloginENCRYPTION: {EncryptionRequired},          // {encryptNotSup},
		preloginINSTOPT:    append([]byte("teleport"), 0), // 0-terminated instance name
		preloginTHREADID:   {0, 0, 0, 0},
		preloginMARS:       {0}, // MARS disabled
	}

	offset := uint16(5*len(fields) + 1)
	keys := make(keySlice, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Sort(keys)

	// writing header
	for _, k := range keys {
		err = w.WriteByte(k)
		if err != nil {
			return err
		}
		err = binary.Write(w, binary.BigEndian, offset)
		if err != nil {
			return err
		}
		v := fields[k]
		size := uint16(len(v))
		err = binary.Write(w, binary.BigEndian, size)
		if err != nil {
			return err
		}
		offset += size
	}

	err = w.WriteByte(preloginTERMINATOR)
	if err != nil {
		return err
	}

	// writing values
	for _, k := range keys {
		v := fields[k]
		written, err := w.Write(v)
		if err != nil {
			return err
		}
		if written != len(v) {
			return errors.New("write method didn't write the whole value")
		}
	}

	// Update packet length.
	pktBytes := w.Bytes()
	binary.BigEndian.PutUint16(pktBytes[2:], uint16(len(pktBytes)))

	fmt.Println("=== SENT PRELOGIN PACKET ===")
	fmt.Println(hex.Dump(pktBytes))
	fmt.Println("=======================")

	// Write packet to connection.
	_, err = conn.Write(pktBytes)
	if err != nil {
		return trace.Wrap(err)
	}

	return nil
}

type keySlice []uint8

func (p keySlice) Len() int           { return len(p) }
func (p keySlice) Less(i, j int) bool { return p[i] < p[j] }
func (p keySlice) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }
