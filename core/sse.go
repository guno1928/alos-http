package core

import "strings"

type SSEWriter struct {
	sw StreamWriter
}

func (r *Response) SSE() *SSEWriter {
	sw := r.EnsureStreamWriter()
	if sw == nil {
		return nil
	}
	headers := [][2]string{
		{"Cache-Control", "no-cache"},
		{"Connection", "keep-alive"},
	}
	sw.WriteHeader(200, headers, "text/event-stream")
	r.SetStreamer(sw)
	return &SSEWriter{sw: sw}
}

func formatSSEData(data string) string {
	if !strings.Contains(data, "\n") {
		return "data: " + data + "\n"
	}
	var b strings.Builder
	lines := strings.Split(data, "\n")
	for _, line := range lines {
		b.WriteString("data: ")
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

func (w *SSEWriter) Send(event, data string) error {
	var b strings.Builder
	b.WriteString("event: ")
	b.WriteString(event)
	b.WriteByte('\n')
	b.WriteString(formatSSEData(data))
	b.WriteByte('\n')
	if err := w.sw.WriteChunk([]byte(b.String())); err != nil {
		return err
	}
	return w.sw.Flush()
}

func (w *SSEWriter) SendData(data string) error {
	var b strings.Builder
	b.WriteString(formatSSEData(data))
	b.WriteByte('\n')
	if err := w.sw.WriteChunk([]byte(b.String())); err != nil {
		return err
	}
	return w.sw.Flush()
}

func (w *SSEWriter) SendID(id, event, data string) error {
	var b strings.Builder
	b.WriteString("id: ")
	b.WriteString(id)
	b.WriteByte('\n')
	b.WriteString("event: ")
	b.WriteString(event)
	b.WriteByte('\n')
	b.WriteString(formatSSEData(data))
	b.WriteByte('\n')
	if err := w.sw.WriteChunk([]byte(b.String())); err != nil {
		return err
	}
	return w.sw.Flush()
}

func (w *SSEWriter) Close() error {
	return w.sw.Close()
}
