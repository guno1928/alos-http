package core

import (
	"bytes"
	"testing"
)

func TestStripInnerPlaintext(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		wantContent []byte
		wantCT      byte
		wantErr     error
	}{
		{
			name:        "no padding",
			data:        []byte{'h', 'i', 0x17},
			wantContent: []byte{'h', 'i'},
			wantCT:      0x17,
		},
		{
			name:        "small zero padding decodes",
			data:        append([]byte{'h', 'i', 0x17}, make([]byte, 8)...),
			wantContent: []byte{'h', 'i'},
			wantCT:      0x17,
		},
		{
			name:        "content-type byte exactly at the cap boundary",
			data:        append([]byte{0x16}, make([]byte, MaxInnerPadding-1)...),
			wantContent: []byte{},
			wantCT:      0x16,
		},
		{
			name:    "excessive padding rejected",
			data:    append([]byte{0x17}, make([]byte, MaxInnerPadding)...),
			wantErr: ErrExcessiveInnerPadding,
		},
		{
			name:    "all-zero short record",
			data:    make([]byte, 8),
			wantErr: ErrAllZeroInner,
		},
		{
			name:    "all-zero over the cap is excessive, not all-zero",
			data:    make([]byte, MaxInnerPadding+64),
			wantErr: ErrExcessiveInnerPadding,
		},
		{
			name:    "empty record",
			data:    []byte{},
			wantErr: ErrAllZeroInner,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			content, ct, err := StripInnerPlaintext(tc.data)
			if err != tc.wantErr {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if tc.wantErr != nil {
				return
			}
			if ct != tc.wantCT {
				t.Errorf("contentType = %#x, want %#x", ct, tc.wantCT)
			}
			if !bytes.Equal(content, tc.wantContent) {
				t.Errorf("content = %v, want %v", content, tc.wantContent)
			}
		})
	}
}
