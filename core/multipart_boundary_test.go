//go:build linux && amd64

package core

import (
	"bytes"
	"errors"
	"io"
	"reflect"
	"testing"
)

const multipartFieldPart = "Content-Disposition: form-data; name=\"field\"\r\n\r\nvalue\r\n"

func multipartDifferentialBodies() map[string]string {
	normal := string(buildMultipart("B",
		multipartFixturePart{disposition: `form-data; name="field"`, body: "value"},
		multipartFixturePart{disposition: `form-data; name="upload"; filename="a.bin"`, contentType: "application/octet-stream", body: "data"},
	))
	withContent := func(content string) string {
		return string(buildMultipart("B",
			multipartFixturePart{disposition: `form-data; name="field"`, body: content},
			multipartFixturePart{disposition: `form-data; name="upload"; filename="a.bin"`, body: content},
			multipartFixturePart{disposition: `form-data; name="after"`, body: "kept"},
		))
	}
	return map[string]string{
		"normal":                           normal,
		"preamble_close_prefix":            "--B--x\r\n" + normal,
		"preamble_line_close_prefix":       "ignored\r\n--B--junk\r\n" + normal,
		"preamble_close_prefix_lwsp_junk":  "--B-- \tjunk\r\n" + normal,
		"preamble_open_prefix":             "--Bwrong\r\n" + normal,
		"preamble_open_prefix_lines":       "text\r\n--Bwrong\r\n--B-x\r\n" + normal,
		"preamble_open_lwsp_junk":          "--B \tjunk\r\n" + normal,
		"preamble_close_line":              "--B--\r\n" + normal,
		"preamble_close_eof":               "--B--",
		"preamble_close_lwsp_eof":          "--B-- \t",
		"preamble_open_eof":                "--B",
		"preamble_open_lwsp_eof":           "--B \t",
		"preamble_only":                    "preamble only",
		"preamble_inline_boundary":         "ignored--B\r\n" + multipartFieldPart + "--B--",
		"open_padding":                     "--B \t\r\n" + multipartFieldPart + "--B-- \t\r\n",
		"close_junk":                       "--B\r\n" + multipartFieldPart + "--B--junk\r\n",
		"close_lwsp_junk":                  "--B\r\n" + multipartFieldPart + "--B-- \tjunk\r\n",
		"close_bare_cr":                    "--B\r\n" + multipartFieldPart + "--B--\r",
		"close_eof":                        "--B\r\n" + multipartFieldPart + "--B--",
		"close_lwsp_eof":                   "--B\r\n" + multipartFieldPart + "--B-- \t",
		"close_epilogue":                   "--B\r\n" + multipartFieldPart + "--B--\r\nignored",
		"close_missing":                    "--B\r\n" + multipartFieldPart + "--B",
		"close_single_dash_eof":            "--B\r\n" + multipartFieldPart + "--B-",
		"next_open_lwsp_junk":              "--B\r\n" + multipartFieldPart + "--B \tjunk\r\n" + multipartFieldPart + "--B--\r\n",
		"content_open_prefix":              withContent("first\r\n--Bnot-a-delimiter\r\nlast"),
		"content_single_dash":              withContent("first\r\n--B-junk\r\nlast"),
		"content_binary_suffix":            withContent("first\r\n--B\x00junk\r\nlast"),
		"content_repeated_prefixes":        withContent("first\r\n--Bwrong\r\n--Bmore\r\nlast"),
		"content_leading_prefix":           withContent("--Bx\r\nlast"),
		"content_empty":                    withContent(""),
		"content_close_junk":               withContent("first\r\n--B--junk\r\nlast"),
		"content_open_lwsp_junk":           withContent("first\r\n--B \tjunk\r\nlast"),
		"content_close_lwsp_junk":          withContent("first\r\n--B-- \tjunk\r\nlast"),
		"content_open_cr_junk":             withContent("first\r\n--B\rjunk\r\nlast"),
		"content_open_tab_junk":            withContent("first\r\n--B\tjunk\r\nlast"),
		"content_true_close":               withContent("first\r\n--B--\r\nlast"),
		"empty_part_without_crlf":          "--B\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n--B\r\n" + multipartFieldPart + "--B--\r\n",
		"empty_file_closed_without_crlf":   "--B\r\nContent-Disposition: form-data; filename=\"../../x\"; name=\"f\"\r\n\r\n--B--",
		"empty_part_bad_line_without_crlf": "--B\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n--B--junk\r\n",
	}
}

func TestMultipartMatchesStdlibOnTrickyBoundaries(t *testing.T) {
	for name, body := range multipartDifferentialBodies() {
		t.Run(name, func(t *testing.T) {
			if hasBareLF([]byte(body)) {
				t.Fatalf("fixture contains a bare LF")
			}
			values, files, err := parseMultipartInMem([]byte(body), "B")
			refValues, refFiles, refErr := parseMultipartStdlibReference([]byte(body), "B")
			if (err == nil) != (refErr == nil) {
				t.Fatalf("inmem err=%v values=%q, stdlib err=%v values=%q", err, values, refErr, refValues)
			}
			if err != nil {
				if !errors.Is(err, errMultipartMalformed) {
					t.Fatalf("inmem err=%v, want errMultipartMalformed", err)
				}
				return
			}
			if !reflect.DeepEqual(values, refValues) || !reflect.DeepEqual(files, refFiles) {
				t.Fatalf("inmem values=%q files=%+v, stdlib values=%q files=%+v", values, files, refValues, refFiles)
			}
		})
	}
}

func TestMultipartClosingBoundaryPrefixDoesNotEndPreamble(t *testing.T) {
	want := map[string][]string{"0": {""}}
	for _, prefix := range []string{"--B--x\r\n", "ignored\r\n--B--junk\r\n", "--B-- \tjunk\r\n", "--Bwrong\r\n"} {
		body := append([]byte(prefix), buildMultipart("B", multipartFixturePart{disposition: `form-data; name="0"`, body: ""})...)
		values, _, err := parseMultipartInMem(body, "B")
		if err != nil || !reflect.DeepEqual(values, want) {
			t.Errorf("prefix %q: values=%q err=%v, want %q", prefix, values, err, want)
		}
	}
}

func TestMultipartMalformedClosingBoundaryIsRejected(t *testing.T) {
	for _, ending := range []string{"--B--junk\r\n", "--B-- \tjunk\r\n", "--B--\r"} {
		body := []byte("--B\r\n" + multipartFieldPart + ending)
		if values, _, err := parseMultipartInMem(body, "B"); !errors.Is(err, errMultipartMalformed) {
			t.Errorf("closing line %q accepted with values=%q", ending, values)
		}
	}
}

func TestMultipartBoundaryPrefixesRemainPartContent(t *testing.T) {
	for _, content := range []string{"first\r\n--Bnot-a-delimiter\r\nlast", "first\r\n--B-junk\r\nlast", "first\r\n--B\x00junk\r\nlast", "first\r\n--Bwrong\r\n--Bmore\r\nlast"} {
		body := buildMultipart("B",
			multipartFixturePart{disposition: `form-data; name="field"`, body: content},
			multipartFixturePart{disposition: `form-data; name="upload"; filename="a.bin"`, body: content},
			multipartFixturePart{disposition: `form-data; name="after"`, body: "kept"},
		)
		values, files, err := parseMultipartInMem(body, "B")
		if err != nil || !reflect.DeepEqual(values, map[string][]string{"field": {content}, "after": {"kept"}}) || len(files["upload"]) != 1 || !bytes.Equal(files["upload"][0].Data, []byte(content)) {
			t.Errorf("content %q: values=%q files=%+v err=%v", content, values, files, err)
		}
	}
}

func TestMultipartContentPrefixesRequireTrueClosingBoundary(t *testing.T) {
	for _, content := range []string{"first\r\n--B--junk\r\nlast", "first\r\n--B \tjunk\r\nlast", "first\r\n--B\rjunk\r\nlast", "first\r\n--B\tjunk\r\nlast"} {
		body := buildMultipart("B", multipartFixturePart{disposition: `form-data; name="field"`, body: content})
		if values, _, err := parseMultipartInMem(body, "B"); !errors.Is(err, errMultipartMalformed) {
			t.Errorf("content %q: values=%q err=%v, want malformed", content, values, err)
		}
	}
}

func TestMultipartRequestKeepsFieldsAndEmptyFilesAfterFalseClose(t *testing.T) {
	body := append([]byte("--B--junk\r\n"), buildMultipart("B",
		multipartFixturePart{disposition: `form-data; name="field"`, body: "kept"},
		multipartFixturePart{disposition: `form-data; name="upload"; filename="empty.txt"`, body: ""},
	)...)
	req := &Request{Body: body, Headers: [][2]string{{"Content-Type", "multipart/form-data; boundary=B"}}}
	if value := req.FormValue("field"); value != "kept" {
		t.Fatalf("FormValue=%q, want kept", value)
	}
	file, found := req.FormFile("upload")
	if !found || file.Filename != "empty.txt" || file.Size != 0 || len(file.Data) != 0 {
		t.Fatalf("empty upload=%+v, found=%v", file, found)
	}
	reader, err := file.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if data, err := io.ReadAll(reader); err != nil || len(data) != 0 {
		t.Fatalf("empty upload reader: %d bytes, err=%v", len(data), err)
	}
}

func TestMultipartRequestDiscardsMalformedClosingFields(t *testing.T) {
	for _, body := range []string{"--B\r\n" + multipartFieldPart + "--B--junk\r\n", string(buildMultipart("B", multipartFixturePart{disposition: `form-data; name="field"`, body: "first\r\n--B--junk\r\nlast"}))} {
		req := &Request{Body: []byte(body), Headers: [][2]string{{"Content-Type", "multipart/form-data; boundary=B"}}}
		if value := req.FormValue("field"); value != "" || len(req.formCache) != 0 || len(req.filesCache) != 0 {
			t.Errorf("body %q exposed partial form value %q", body, value)
		}
	}
}
