package core

import "strings"

// SSEWriter streams Server-Sent Events to the client. Obtain one from
// Response.SSE and emit events with Send, SendData, or SendID.
type SSEWriter struct {
	sw StreamWriter
}

// SSE switches the response into Server-Sent Events mode, writing the
// text/event-stream headers, and returns an SSEWriter. Returns nil if the
// connection does not support streaming.
//
// Example: sse := resp.SSE(); if sse == nil { return }
// Example: sse := resp.SSE(); defer sse.Close()
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

func sseStripField(s string) string {
	if strings.IndexByte(s, '\n') < 0 && strings.IndexByte(s, '\r') < 0 {
		return s
	}
	return strings.NewReplacer("\r", "", "\n", "").Replace(s)
}

// Send writes a named event with a data payload and flushes it to the client.
//
// Example: sse.Send("message", "hello")
// Example: sse.Send("update", `{"count":5}`)
func (w *SSEWriter) Send(event, data string) error {
	var b strings.Builder
	b.WriteString("event: ")
	b.WriteString(sseStripField(event))
	b.WriteByte('\n')
	b.WriteString(formatSSEData(data))
	b.WriteByte('\n')
	if err := w.sw.WriteChunk([]byte(b.String())); err != nil {
		return err
	}
	return w.sw.Flush()
}

// SendData writes an unnamed data-only event and flushes it to the client.
//
// Example: sse.SendData("tick")
// Example: sse.SendData("line1\nline2")
func (w *SSEWriter) SendData(data string) error {
	var b strings.Builder
	b.WriteString(formatSSEData(data))
	b.WriteByte('\n')
	if err := w.sw.WriteChunk([]byte(b.String())); err != nil {
		return err
	}
	return w.sw.Flush()
}

// SendID writes an event carrying an id field, allowing clients to resume with
// Last-Event-ID, and flushes it to the client.
//
// Example: sse.SendID("42", "message", "hello")
// Example: sse.SendID("e1", "update", `{"ok":true}`)
func (w *SSEWriter) SendID(id, event, data string) error {
	var b strings.Builder
	b.WriteString("id: ")
	b.WriteString(sseStripField(id))
	b.WriteByte('\n')
	b.WriteString("event: ")
	b.WriteString(sseStripField(event))
	b.WriteByte('\n')
	b.WriteString(formatSSEData(data))
	b.WriteByte('\n')
	if err := w.sw.WriteChunk([]byte(b.String())); err != nil {
		return err
	}
	return w.sw.Flush()
}

// Close ends the event stream and closes the underlying connection.
func (w *SSEWriter) Close() error {
	return w.sw.Close()
}
