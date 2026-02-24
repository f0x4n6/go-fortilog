// Package fortilog
// This code was transpiled from the original Python implementation and works with my elog and tlog test files. Still it is nowhere near as clean or optimized as it could and probably should be, and I would only trust the transpiler as far as I can piss on a hot summers day.
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

var magic = [][]byte{
	{0xEC, 0xCF},
	{0xEC, 0xDE},
}

var tlcFields = []string{
	"",
	"devid",
	"devname",
	"vdom",
	"devtype",
	"logtype",
	"tmzone",
	"fazid",
	"srcip",
	"unused?",
	"unused?",
	"num-logs",
	"unzip-len",
	"incr-zip",
	"unzip-len-p",
	"prefix",
	"zbuf",
	"logs",
}

func DecodeLLogV5(data []byte, out *bytes.Buffer) error {
	reader := bytes.NewReader(data)
	var logEntries int

	for {
		// Peek at next 2 bytes to determine type
		logType := make([]byte, 2)
		n, err := reader.Read(logType)
		if err == io.EOF || n < 2 {
			break
		}
		if err != nil {
			return err
		}
		_, _ = reader.Seek(-2, io.SeekCurrent) // Unread for processing

		if bytes.Equal(logType, magic[0]) || bytes.Equal(logType, magic[1]) {
			// Consume magic bytes
			_, _ = reader.Read(logType)

			head := make([]byte, 16)
			if _, err := io.ReadFull(reader, head); err != nil {
				return err
			}

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

			var tzLen int
			if bytes.Equal(logType, magic[1]) { // 0xECDE
				_, _ = reader.Seek(10, io.SeekCurrent)
				tzByte, _ := reader.ReadByte()
				tzLen = int(tzByte)
			}

			lASCII := lDevID + lDevName + lVDOM
			body := make([]byte, lASCII+lEntryCounts+lSomething)
			if _, err := io.ReadFull(reader, body); err != nil {
				return err
			}

			devID := string(body[0:lDevID])
			devName := string(body[lDevID : lDevID+lDevName])
			vdom := string(body[lDevID+lDevName : lDevID+lDevName+lVDOM])
			entriesLengths := body[lASCII : lASCII+lEntryCounts]

			if bytes.Equal(logType, magic[1]) && tzLen > 0 {
				_, _ = reader.Seek(int64(tzLen), io.SeekCurrent)
			}

			compressed := make([]byte, lCompressed)
			if _, err := io.ReadFull(reader, compressed); err != nil {
				return err
			}

			decompressed := make([]byte, lDecompressed+1)
			uncomp, err := lz4.UncompressBlock(compressed, decompressed)
			if err != nil {
				// Skip this entry on decompression error, continue processing
				continue
			}
			decompressed = decompressed[:uncomp]

			prefix := fmt.Sprintf(`devid="%s" devname="%s" vdom="%s" `, devID, devName, vdom)

			if entryCount > 1 {
				pointer := 0
				for i := 0; i < lEntryCounts; i += 2 {
					l := int(binary.BigEndian.Uint16(entriesLengths[i : i+2]))
					out.WriteString(prefix)
					out.Write(decompressed[pointer : pointer+l])
					out.WriteByte(0x0a)
					pointer += l
					logEntries++
				}
			} else if entryCount == 1 {
				out.WriteString(prefix)
				out.Write(decompressed)
				out.WriteByte(0x0a)
				logEntries++
			}

			// Skip 2nd variable part
			head2 := make([]byte, 2)
			if _, err := io.ReadFull(reader, head2); err != nil {
				continue
			}
			body2 := binary.LittleEndian.Uint16(head2)
			_, _ = reader.Seek(int64(body2), io.SeekCurrent)

		} else if bytes.Equal(logType, []byte{0xAA, 0x01}) {
			_, _ = reader.Seek(4, io.SeekCurrent) // Skip magic + 2 bytes

			lBodyBytes := make([]byte, 4)
			if _, err := io.ReadFull(reader, lBodyBytes); err != nil {
				return err
			}
			lBody := int(binary.BigEndian.Uint32(lBodyBytes)) - 8

			body := make([]byte, lBody)
			if _, err := io.ReadFull(reader, body); err != nil {
				return err
			}

			tlc, err := parseTLC(body)
			if err != nil {
				continue
			}

			rawEntries := bytes.Split(tlc, []byte{0x00})
			for _, rawEntry := range rawEntries {
				idx := bytes.Index(rawEntry, []byte("date="))
				if idx == -1 {
					continue
				}
				out.Write(rawEntry[idx:])
				out.WriteByte(0x0a)
				logEntries++
			}

		} else if bytes.Equal(logType, []byte{0x00, 0x00}) || logType[0] == 0x00 {
			_, _ = reader.ReadByte()
			continue
		} else {
			return fmt.Errorf("log type not supported: %x", logType)
		}
	}

	return nil
}

func parseTLC(body []byte) ([]byte, error) {
	pointer := 0
	var lUnzipped int

	for pointer < len(body) {
		if pointer >= len(body) {
			break
		}
		typeHigh := body[pointer] >> 4
		pointer++

		if pointer >= len(body) {
			break
		}
		fieldID := body[pointer]
		pointer++

		var value int64
		var array []byte

		if typeHigh <= 2 {
			var lArray int
			switch typeHigh {
			case 0:
				if pointer >= len(body) {
					return nil, fmt.Errorf("unexpected EOF")
				}
				lArray = int(body[pointer])
				pointer++
			case 1:
				if pointer+2 > len(body) {
					return nil, fmt.Errorf("unexpected EOF")
				}
				lArray = int(binary.BigEndian.Uint16(body[pointer : pointer+2]))
				pointer += 2
			case 2:
				if pointer+4 > len(body) {
					return nil, fmt.Errorf("unexpected EOF")
				}
				lArray = int(binary.BigEndian.Uint32(body[pointer : pointer+4]))
				pointer += 4
			}
			if pointer+lArray > len(body) {
				return nil, fmt.Errorf("unexpected EOF")
			}
			array = body[pointer : pointer+lArray]
			pointer += lArray
		} else if typeHigh == 3 {
			if pointer >= len(body) {
				return nil, fmt.Errorf("unexpected EOF")
			}
			value = int64(body[pointer])
			pointer++
		} else if typeHigh == 4 {
			if pointer+2 > len(body) {
				return nil, fmt.Errorf("unexpected EOF")
			}
			value = int64(binary.BigEndian.Uint16(body[pointer : pointer+2]))
			pointer += 2
		} else if typeHigh == 5 {
			if pointer+4 > len(body) {
				return nil, fmt.Errorf("unexpected EOF")
			}
			value = int64(binary.BigEndian.Uint32(body[pointer : pointer+4]))
			pointer += 4
		} else if typeHigh == 6 {
			if pointer+8 > len(body) {
				return nil, fmt.Errorf("unexpected EOF")
			}
			value = int64(binary.BigEndian.Uint64(body[pointer : pointer+8]))
			pointer += 8
		} else {
			return nil, fmt.Errorf("type not supported: %x", typeHigh)
		}

		fieldName := ""
		if int(fieldID) < len(tlcFields) {
			fieldName = tlcFields[fieldID]
		}

		if fieldName == "unzip-len" {
			lUnzipped = int(value)
		} else if fieldName == "zbuf" {
			if lUnzipped == 0 || len(array) == 0 {
				return nil, fmt.Errorf("invalid zbuf")
			}

			decompressed := make([]byte, lUnzipped)
			lz4Reader := lz4.NewReader(bytes.NewReader(array))
			n, err := io.ReadFull(lz4Reader, decompressed)
			if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
				return nil, err
			}
			return decompressed[:n], nil
		}
	}

	return nil, fmt.Errorf("zbuf not found")
}
