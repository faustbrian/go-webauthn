package webauthn

import (
	"math"
	"unicode/utf8"
)

// This selected CTAP/WebAuthn profile accepts definite-length RFC8949 data,
// rejecting duplicate keys and unsupported tags/floats before crypto. Limits
// are pinned in PROTOCOL_CONFORMANCE_MANIFEST, not library decoder defaults.
type cborReader struct {
	wire          []byte
	offset, items int
}

func (r *cborReader) read(depth int) (any, error) {
	if depth > 16 || r.items >= 256 || r.offset >= len(r.wire) {
		return nil, Invalid{Field: "cbor"}
	}
	r.items++
	b := r.wire[r.offset]
	r.offset++
	major, ai := b>>5, b&31
	if ai >= 28 {
		return nil, Invalid{Field: "cbor"}
	}
	n := uint64(ai)
	if ai >= 24 {
		size := 1 << uint(ai-24)
		if size > 8 || size > len(r.wire)-r.offset {
			return nil, Invalid{Field: "cbor"}
		}
		n = 0
		for _, v := range r.wire[r.offset : r.offset+size] {
			n = n<<8 | uint64(v)
		}
		r.offset += size
	}
	switch major {
	case 0:
		return n, nil
	case 1:
		if n > math.MaxInt64 {
			return nil, Invalid{Field: "cbor_integer"}
		}
		return -1 - int64(n), nil
	case 2, 3:
		if n > uint64(len(r.wire)-r.offset) {
			return nil, Invalid{Field: "cbor_length"}
		}
		v := r.wire[r.offset : r.offset+int(n)]
		r.offset += int(n)
		if major == 2 {
			return v, nil
		}
		if !utf8.Valid(v) {
			return nil, Invalid{Field: "cbor_text"}
		}
		return string(v), nil
	case 4:
		if n > 256 || n > uint64(256-r.items) {
			return nil, Invalid{Field: "cbor_items"}
		}
		out := make([]any, int(n))
		for i := range out {
			v, e := r.read(depth + 1)
			if e != nil {
				return nil, e
			}
			out[i] = v
		}
		return out, nil
	case 5:
		if n > 128 || n > uint64((256-r.items)/2) {
			return nil, Invalid{Field: "cbor_items"}
		}
		out := make(map[any]any, int(n))
		for range int(n) {
			k, e := r.read(depth + 1)
			if e != nil {
				return nil, e
			}
			switch k.(type) {
			case string, uint64, int64:
			default:
				return nil, Invalid{Field: "cbor_key"}
			}
			if _, ok := out[k]; ok {
				return nil, Invalid{Field: "cbor_duplicate"}
			}
			v, e := r.read(depth + 1)
			if e != nil {
				return nil, e
			}
			out[k] = v
		}
		return out, nil
	case 7:
		switch b {
		case 0xf4:
			return false, nil
		case 0xf5:
			return true, nil
		case 0xf6:
			return nil, nil
		}
	}
	return nil, Invalid{Field: "cbor_type"}
}
func parseCBOR(wire []byte) (map[any]any, error) {
	r := cborReader{wire: wire}
	v, e := r.read(0)
	if e != nil {
		return nil, e
	}
	m, ok := v.(map[any]any)
	if !ok || r.offset != len(wire) {
		return nil, Invalid{Field: "cbor_map"}
	}
	return m, nil
}
func cborInteger(v any) (int64, bool) {
	switch n := v.(type) {
	case int64:
		return n, true
	case uint64:
		if n <= math.MaxInt64 {
			return int64(n), true
		}
	}
	return 0, false
}
