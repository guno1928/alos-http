//go:build linux && amd64

package core

import "testing"

func TestAppendH2SettingsFlightUsesConfig(t *testing.T) {
	s := New(Config{H2MaxConcurrentStreams: 111, H2InitialWindowSize: 200000, H2MaxFrameSize: 20000})
	m := decodeH2Settings(appendH2ServerSettingsFlight(nil, s))
	if m[uint16(H2SettingMaxConcurrentStreams)] != 111 {
		t.Fatalf("flight streams = %d, want 111", m[uint16(H2SettingMaxConcurrentStreams)])
	}
	if m[uint16(H2SettingInitialWindowSize)] != 200000 {
		t.Fatalf("flight window = %d, want 200000", m[uint16(H2SettingInitialWindowSize)])
	}
	if m[uint16(H2SettingMaxFrameSize)] != 20000 {
		t.Fatalf("flight frame = %d, want 20000", m[uint16(H2SettingMaxFrameSize)])
	}
}

func TestAppendH2SettingsFlightDefaults(t *testing.T) {
	m := decodeH2Settings(appendH2ServerSettingsFlight(nil, New(Config{})))
	if m[uint16(H2SettingMaxConcurrentStreams)] != uint32(H2MaxConcurrentStream) {
		t.Fatalf("default flight streams = %d", m[uint16(H2SettingMaxConcurrentStreams)])
	}
	if m[uint16(H2SettingMaxFrameSize)] != uint32(H2DefaultMaxFrameSize) {
		t.Fatalf("default flight frame = %d", m[uint16(H2SettingMaxFrameSize)])
	}
}
