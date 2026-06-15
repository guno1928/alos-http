package core

func urlDecode(s string) string {
	needsDecode := false
	for i := 0; i < len(s); i++ {
		if s[i] == '%' || s[i] == '+' {
			needsDecode = true
			break
		}
	}
	if !needsDecode {
		return s
	}

	buf := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '+':
			buf = append(buf, ' ')
		case '%':
			if i+2 < len(s) && hexValid[s[i+1]] && hexValid[s[i+2]] {
				buf = append(buf, hexLookup[s[i+1]]<<4|hexLookup[s[i+2]])
				i += 2
			} else {
				buf = append(buf, '%')
			}
		default:
			buf = append(buf, s[i])
		}
	}
	return string(buf)
}

func parseQueryString(query string) map[string][]string {
	m := make(map[string][]string)
	for len(query) > 0 {
		var pair string
		idx := indexByte(query, '&')
		if idx >= 0 {
			pair = query[:idx]
			query = query[idx+1:]
		} else {
			pair = query
			query = ""
		}
		if pair == "" {
			continue
		}
		var key, val string
		eq := indexByte(pair, '=')
		if eq >= 0 {
			key = urlDecode(pair[:eq])
			val = urlDecode(pair[eq+1:])
		} else {
			key = urlDecode(pair)
		}
		m[key] = append(m[key], val)
	}
	return m
}
