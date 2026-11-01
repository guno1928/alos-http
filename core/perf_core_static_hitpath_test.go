//go:build linux && amd64

package core

import "testing"

const perfCoreStaticHeadBufCap = 1024

func BenchmarkPerfCoreStaticHitPath(b *testing.B) {
	perfCoreSettleStaticFiles(b)
	root, _ := perfCoreStaticRoot(b)
	rig := newPerfCoreStaticRig(root, false)
	rig.serve()
	etag, lastModified := "", ""
	for _, h := range rig.resp.Headers {
		switch h[0] {
		case "etag":
			etag = h[1]
		case "last-modified":
			lastModified = h[1]
		}
	}
	if etag == "" || lastModified == "" {
		b.Fatalf("validators missing: %v", rig.resp.Headers)
	}
	cases := []struct {
		name   string
		header [2]string
		status int
	}{
		{"hit_200", [2]string{}, 200},
		{"if_none_match_304", [2]string{"if-none-match", etag}, 304},
		{"if_modified_since_304", [2]string{"if-modified-since", lastModified}, 304},
		{"range_206", [2]string{"range", "bytes=1000-1999"}, 206},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			rig.req.Headers = rig.req.Headers[:0]
			if tc.header[0] != "" {
				rig.req.Headers = append(rig.req.Headers, tc.header)
			}
			b.ReportAllocs()
			for b.Loop() {
				rig.serve()
			}
			if rig.resp.StatusCode != tc.status {
				b.Fatalf("status %d, want %d", rig.resp.StatusCode, tc.status)
			}
		})
	}
	rig.req.Headers = rig.req.Headers[:0]
	rig.serve()
	head := make([]byte, 0, perfCoreStaticHeadBufCap)
	b.Run("h1_head_build", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			head = appendPlainResponseMode(rig.resp, head[:0], true, false)
		}
	})
	var tbl hpackEncTable
	b.Run("h2_head_build", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			head = appendH2ResponseHeadersFrameIndexed(head[:0], 1, rig.resp, false, &tbl, respServerName(rig.resp), H2DefaultMaxFrameSize)
		}
	})
}
