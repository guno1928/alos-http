//go:build linux && amd64

package core

import "math/bits"

const (
	h3MaxFieldSectionSize = 16384
	h3FieldLineOverhead   = 32
	h3AsteriskTarget      = "*"
)

var (
	errH3FieldSectionTooLarge = &staticError{"h3 field section too large"}
	errQPACKDecompression     = &staticError{"qpack decompression failed"}
)

func h3FieldSectionSize(fields [][2]string) int {
	size := 0
	for i := range fields {
		size += len(fields[i][0]) + len(fields[i][1]) + h3FieldLineOverhead
	}
	return size
}

func (s *Server) h3FieldSectionLimit() int {
	return min(h3MaxFieldSectionSize, s.h2HeaderListLimit())
}

func h3ValidateRequestSection(fields [][2]string, limit int) (hpackRequestMeta, error) {
	var meta hpackRequestMeta
	if h3FieldSectionSize(fields) > limit {
		return meta, errH3FieldSectionTooLarge
	}
	for i := range fields {
		if err := meta.observeHeader(fields[i][0], fields[i][1]); err != nil {
			return meta, err
		}
	}
	if err := meta.validate(); err != nil {
		return meta, err
	}
	if !isH1Token(UnsafeBytes(meta.method)) {
		return meta, errH2MalformedRequest
	}
	if meta.pseudoMask&hpackPseudoPath != 0 && !h3ValidRequestTarget(meta.rawPath, meta.method) {
		return meta, errH2MalformedRequest
	}
	return meta, nil
}

func h3ValidRequestTarget(target, method string) bool {
	if target == h3AsteriskTarget {
		return method == "OPTIONS"
	}
	if target == "" || target[0] != '/' {
		return false
	}
	for i := 0; i < len(target); i++ {
		if c := target[i]; c <= ' ' || c == 0x7f {
			return false
		}
	}
	return true
}

func h3PseudoFieldCount(meta *hpackRequestMeta) int {
	return bits.OnesCount8(meta.pseudoMask)
}

func h3RequestErrorStatus(err error) int {
	if err == errH3FieldSectionTooLarge || err == ErrTooManyHeaders {
		return 431
	}
	return 400
}

func (h3 *H3Conn) decodeRequestSection(block []byte, req *Request) (hpackRequestMeta, *[]byte, int) {
	limit := h3.server.h3FieldSectionLimit()
	if cached, hit := qpackDecodedBlocks.get(block); hit {
		if cached.fieldSectionSize > limit {
			return hpackRequestMeta{}, nil, h3RequestErrorStatus(errH3FieldSectionTooLarge)
		}
		req.Headers = append(req.Headers, cached.regular...)
		return cached.meta, nil, 0
	}
	fields, arena, err := h3.decoder.DecodeAppend(block, req.Headers)
	if err != nil {
		if debugFlag.Load() {
			Dbg("[H3] QPACK decode error: %v", err)
		}
		return hpackRequestMeta{}, arena, h3RequestErrorStatus(err)
	}
	meta, err := h3ValidateRequestSection(fields, limit)
	if err != nil {
		return meta, arena, h3RequestErrorStatus(err)
	}
	qpackDecodedBlocks.put(block, fields)
	req.Headers = append(fields[:0], fields[h3PseudoFieldCount(&meta):]...)
	return meta, arena, 0
}

func (h3 *H3Conn) decodeTrailerSection(block []byte, req *Request) (*[]byte, int) {
	fields, arena, err := h3.decoder.DecodeAppend(block, nil)
	if err != nil {
		return arena, h3RequestErrorStatus(err)
	}
	if h3FieldSectionSize(fields) > h3.server.h3FieldSectionLimit() {
		return arena, h3RequestErrorStatus(errH3FieldSectionTooLarge)
	}
	trailers, ok := h2TrailerFields(fields)
	if !ok {
		return arena, 400
	}
	req.trailers = trailers
	return arena, 0
}
