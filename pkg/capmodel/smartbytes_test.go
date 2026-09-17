package capmodel

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSmartBytes_TextMarshalsAsPlainString(t *testing.T) {
	f := File{Name: "definitions/x", Bytes: []byte("## Vulnerability Description\nhello")}
	b, err := json.Marshal(f)
	require.NoError(t, err)
	require.Equal(t, `{"name":"definitions/x","bytes":"## Vulnerability Description\nhello"}`, string(b))
}

func TestSmartBytes_BinaryMarshalsWithBase64Prefix(t *testing.T) {
	f := File{Name: "x.png", Bytes: []byte{0x89, 0x50, 0x4e, 0x47, 0x00, 0x01}}
	b, err := json.Marshal(f)
	require.NoError(t, err)
	// Non-UTF-8/control bytes must be encoded behind the "base64:" prefix so the
	// chariot side (model.File.Bytes SmartBytes) decodes them losslessly.
	require.Equal(t, `{"name":"x.png","bytes":"base64:iVBORwAB"}`, string(b))
}

func TestSmartBytes_RoundTrip(t *testing.T) {
	cases := [][]byte{
		[]byte("plain text\n"),
		[]byte("base64:dGVzdA=="),
		[]byte("base64:not-valid-base64"),
		{0x00, 0x01, 0x02, 0xff, 0xfe},
		{},
	}
	for _, input := range cases {
		encoded, err := json.Marshal(File{Name: "f", Bytes: input})
		require.NoError(t, err)

		var output File
		require.NoError(t, json.Unmarshal(encoded, &output))
		require.Equal(t, SmartBytes(input), output.Bytes)
	}
}
