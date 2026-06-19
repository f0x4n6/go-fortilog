package fortilog

import (
	"bytes"
	"compress/gzip"
	"io"
	"log"
	"os"
	"testing"
)

func TestDecodeLLogV5(t *testing.T) {
	for _, tt := range []struct {
		name string
		path string
		gold string
	}{
		{
			name: "elog",
			path: "../testdata/elog.1706300000.log.gz",
			gold: "../testdata/elog.1706300000.gld.gz",
		},
		{
			name: "tlog",
			path: "../testdata/tlog.1706300000.log.gz",
			gold: "../testdata/tlog.1706300000.gld.gz",
		},
	} {
		t.Run("Test DecodeLLogV5 "+tt.name, func(t *testing.T) {
			data := fixture(tt.path)
			gold := fixture(tt.gold)

			buf := bytes.NewBuffer(nil)
			err := DecodeLLogV5(data, buf)

			if err != nil {
				t.Fatal(err)
			}

			if bytes.Compare(buf.Bytes(), gold) != 0 {
				t.Fatal("sample mismatch")
			}
		})
	}
}

func BenchmarkDecodeLLogV5(b *testing.B) {
	bin := fixture("../testdata/elog.1706300000.log.gz")
	buf := bytes.NewBuffer(nil)

	b.ResetTimer()

	b.Run("Benchmark DecodeLLogV5", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			_ = DecodeLLogV5(bin, buf)
		}
	})
}

func fixture(path string) []byte {
	f, err := os.ReadFile(path)

	if err != nil {
		log.Fatalln(err.Error())
	}

	r, err := gzip.NewReader(bytes.NewReader(f))

	if err != nil {
		log.Fatalln(err.Error())
	}

	b, err := io.ReadAll(r)

	if err != nil {
		log.Fatalln(err.Error())
	}

	err = r.Close()

	if err != nil {
		log.Fatalln(err.Error())
	}

	return b
}
