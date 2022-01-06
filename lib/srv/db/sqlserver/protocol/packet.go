/*
Copyright 2022 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package protocol

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/gravitational/trace"
)

type PacketHeader struct {
	Type     uint8
	Status   uint8
	Length   uint16
	SPID     uint16
	PacketID uint8
	Window   uint8
}

type Packet struct {
	// Header
	PacketHeader

	// Data
	Data []byte
}

func ReadPacket(conn io.Reader) (*Packet, error) {
	fmt.Println("=== Reading packet header ===")

	// Read 8-byte packet header.
	var header [packetHeaderSize]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return nil, trace.ConvertSystemError(err)
	}

	// Build out packet header.
	pkt := Packet{
		PacketHeader: PacketHeader{
			Type:     header[0],
			Status:   header[1],
			Length:   binary.BigEndian.Uint16(header[2:4]),
			SPID:     binary.BigEndian.Uint16(header[4:6]),
			PacketID: header[6],
			Window:   header[7],
		},
	}

	// fmt.Printf("== Packet header: %#v\n", pkt)

	// Read packet data. Packet length includes header.
	pkt.Data = make([]byte, pkt.Length-packetHeaderSize)
	_, err := io.ReadFull(conn, pkt.Data)
	if err != nil {
		return nil, trace.ConvertSystemError(err)
	}

	fmt.Println(hex.Dump(append(header[:], pkt.Data...)))

	return &pkt, nil
}

const (
	PacketTypeResponse uint8 = 4  // 0x04
	PacketTypeLogin7   uint8 = 16 // 0x10
	PacketTypePreLogin uint8 = 18 // 0x12

	packetHeaderSize = 8
)
