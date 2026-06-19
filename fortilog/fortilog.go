// Package fortilog
//
// This code was transpiled from the original Python implementation
// and works with my synthetic elog and tlog test files.
// Still it is nowhere near as clean or optimized as it could
// and probably should be, and I would only trust the transpiler
// as far as I can piss on a hot summers day.
//
// Sources:
// https://cyber.wtf/2024/08/30/parsing-fortinet-binary-firewall-logs/
// https://github.com/GDATAAdvancedAnalytics/FortilogDecoder/blob/main/fortilog_decoder.py
package fortilog

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/pierrec/lz4/v4"
)

var ErrDataStream = errors.New("data stream error")

var magic = [][]byte{
	{0xEC, 0xCF},
	{0xEC, 0xDE},
}

var fields = []string{
	"",
	"devid",
	"devname",
	"vdom",
	"devtype",
	"logtype",
	"tmzone",
	"fazid",
	"srcip",
	"reserved",
	"reserved",
	"num-logs",
	"unzip-len",
	"incr-zip",
	"unzip-len-p",
	"prefix",
	"zbuf",
	"logs",
}

func DecodeLLogV5(b []byte, buf *bytes.Buffer) error {
	r := bytes.NewReader(b)

	for {
		// peek at next 2 bytes to determine type
		logType := make([]byte, 2)
		n, err := r.Read(logType)

		// data stream end
		if err == io.EOF || n < 2 {
			break
		}

		// data stream error
		if err != nil {
			return ErrDataStream
		}

		// unread for processing
		if _, err = r.Seek(-2, io.SeekCurrent); err != nil {
			return ErrDataStream
		}

		// check supported log types
		if bytes.Equal(logType, magic[0]) || bytes.Equal(logType, magic[1]) {
			// consume magic bytes
			if _, err = r.Read(logType); err != nil {
				return ErrDataStream
			}

			// read log header
			head := make([]byte, 16)
			if _, err = io.ReadFull(r, head); err != nil {
				return ErrDataStream
			}

			// parse header fields
			flag := (head[0] >> 2) & 1
			lDevID := int(head[3])
			lDevName := int(head[4])
			lVDOM := int(head[5])
			entryCount := int(binary.BigEndian.Uint16(head[6:8]))
			lEntryCounts := entryCount * 2
			lSomething := 0
			if flag != 0 {
				lSomething = lEntryCounts
			}
			lCompressed := int(binary.BigEndian.Uint16(head[8:10]))
			lDecompressed := int(binary.BigEndian.Uint16(head[10:12]))

			// read log body
			var tzLen int
			if bytes.Equal(logType, magic[1]) {
				if _, err = r.Seek(10, io.SeekCurrent); err != nil {
					return ErrDataStream
				}
				tzByte, _ := r.ReadByte()
				tzLen = int(tzByte)
			}
			lASCII := lDevID + lDevName + lVDOM
			body := make([]byte, lASCII+lEntryCounts+lSomething)
			if _, err = io.ReadFull(r, body); err != nil {
				return ErrDataStream
			}

			// parse body fields
			devID := string(body[0:lDevID])
			devName := string(body[lDevID : lDevID+lDevName])
			vdom := string(body[lDevID+lDevName : lDevID+lDevName+lVDOM])
			entriesLengths := body[lASCII : lASCII+lEntryCounts]
			if bytes.Equal(logType, magic[1]) && tzLen > 0 {
				if _, err = r.Seek(int64(tzLen), io.SeekCurrent); err != nil {
					return ErrDataStream
				}
			}

			// read compressed entries
			compressed := make([]byte, lCompressed)
			if _, err = io.ReadFull(r, compressed); err != nil {
				return ErrDataStream
			}

			// decompress entries
			decompressed := make([]byte, lDecompressed+1)
			uncomp, err := lz4.UncompressBlock(compressed, decompressed)
			if err != nil {
				return ErrDataStream
			}

			// parse entries
			decompressed = decompressed[:uncomp]
			prefix := fmt.Sprintf(`devid="%s" devname="%s" vdom="%s" `, devID, devName, vdom)
			if entryCount > 1 {
				pointer := 0
				for i := 0; i < lEntryCounts; i += 2 {
					l := int(binary.BigEndian.Uint16(entriesLengths[i : i+2]))
					buf.WriteString(prefix)
					buf.Write(decompressed[pointer : pointer+l])
					buf.WriteByte(0x0a)
					pointer += l
				}
			} else if entryCount == 1 {
				buf.WriteString(prefix)
				buf.Write(decompressed)
				buf.WriteByte(0x0a)
			}

			// forward data stream
			head2 := make([]byte, 2)
			if _, err = io.ReadFull(r, head2); err != nil {
				return ErrDataStream
			}

			// forward data stream
			body2 := binary.LittleEndian.Uint16(head2)
			if _, err = r.Seek(int64(body2), io.SeekCurrent); err != nil {
				return ErrDataStream
			}
		} else if bytes.Equal(logType, []byte{0xAA, 0x01}) {
			// skip magic and two bytes
			if _, err = r.Seek(4, io.SeekCurrent); err != nil {
				return ErrDataStream
			}

			// read log body size
			lBodyBytes := make([]byte, 4)
			if _, err = io.ReadFull(r, lBodyBytes); err != nil {
				return ErrDataStream
			}

			// read log body
			lBody := int(binary.BigEndian.Uint32(lBodyBytes)) - 8
			body := make([]byte, lBody)
			if _, err = io.ReadFull(r, body); err != nil {
				return ErrDataStream
			}

			// parse tlc logs
			tlc, err := DecodeTLC(body)
			if err != nil {
				return ErrDataStream
			}

			// parse tlc entries
			rawEntries := bytes.Split(tlc, []byte{0x00})
			for _, rawEntry := range rawEntries {
				if len(rawEntry) == 0 {
					continue
				}
				idx := bytes.Index(rawEntry, []byte("date="))
				if idx == -1 {
					continue
				}
				buf.Write(rawEntry[idx:])
				buf.WriteByte(0x0a)
			}
		} else if bytes.Equal(logType, []byte{0x00, 0x00}) || logType[0] == 0x00 {
			if _, err = r.ReadByte(); err != nil {
				return ErrDataStream
			}
			continue
		} else {
			return fmt.Errorf("log type not supported: %x", logType)
		}
	}

	return nil
}

func DecodeTLC(b []byte) ([]byte, error) {
	var lUnzipped int

	for i := 0; i < len(b); {
		// read type
		if i >= len(b) {
			break
		}
		typeHigh := b[i] >> 4
		i++

		// read field id
		if i >= len(b) {
			break
		}
		fieldId := b[i]
		i++

		// read array length
		var value int64
		var array []byte
		if typeHigh <= 2 {
			// parse byte array
			var lArray int
			switch typeHigh {
			// parse byte
			case 0:
				if i >= len(b) {
					return nil, ErrDataStream
				}
				lArray = int(b[i])
				i++

			// parse uint16
			case 1:
				if i+2 > len(b) {
					return nil, ErrDataStream
				}
				lArray = int(binary.BigEndian.Uint16(b[i : i+2]))
				i += 2

			// parse uint32
			case 2:
				if i+4 > len(b) {
					return nil, ErrDataStream
				}
				lArray = int(binary.BigEndian.Uint32(b[i : i+4]))
				i += 4
			}

			// read array value
			if i+lArray > len(b) {
				return nil, ErrDataStream
			}
			array = b[i : i+lArray]
			i += lArray
		} else if typeHigh == 3 {
			// parse byte value
			if i >= len(b) {
				return nil, ErrDataStream
			}
			value = int64(b[i])
			i++
		} else if typeHigh == 4 {
			// parse uint16 value
			if i+2 > len(b) {
				return nil, ErrDataStream
			}
			value = int64(binary.BigEndian.Uint16(b[i : i+2]))
			i += 2
		} else if typeHigh == 5 {
			// parse uint32 value
			if i+4 > len(b) {
				return nil, ErrDataStream
			}
			value = int64(binary.BigEndian.Uint32(b[i : i+4]))
			i += 4
		} else if typeHigh == 6 {
			// parse uint64 value
			if i+8 > len(b) {
				return nil, ErrDataStream
			}
			value = int64(binary.BigEndian.Uint64(b[i : i+8]))
			i += 8
		} else {
			return nil, fmt.Errorf("type not supported: %x", typeHigh)
		}

		// read field name
		fieldName := ""
		if int(fieldId) < len(fields) {
			fieldName = fields[fieldId]
		}

		if fieldName == "unzip-len" {
			// read decompressed length
			lUnzipped = int(value)
		} else if fieldName == "zbuf" {
			// decompress field value
			if lUnzipped == 0 || len(array) == 0 {
				return nil, ErrDataStream
			}
			decompressed := make([]byte, lUnzipped)
			lz4Reader := lz4.NewReader(bytes.NewReader(array))
			n, err := io.ReadFull(lz4Reader, decompressed)
			if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
				return nil, ErrDataStream
			}
			return decompressed[:n], nil
		}
	}

	return nil, ErrDataStream
}
