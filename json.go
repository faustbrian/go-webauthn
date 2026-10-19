package webauthn

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"unicode/utf8"
)

// validateJSON bounds nesting/item work and rejects duplicate keys recursively,
// including ignored extension values. json.Unmarshal alone accepts duplicates.
func validateJSON(wire []byte, maximum int) error {
	if len(wire) == 0 || len(wire) > maximum || !utf8.Valid(wire) {
		return Invalid{Field: "json"}
	}
	d := json.NewDecoder(bytes.NewReader(wire))
	d.UseNumber()
	items := 0
	var value func(int) error
	value = func(depth int) error {
		items++
		if depth > 16 || items > 256 {
			return Invalid{Field: "json_limits"}
		}
		t, e := d.Token()
		if e != nil {
			return Invalid{Field: "json"}
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				items++
				if items > 256 {
					return Invalid{Field: "json_limits"}
				}
				k, e := d.Token()
				if e != nil {
					return Invalid{Field: "json"}
				}
				s, ok := k.(string)
				if !ok || seen[s] {
					return Invalid{Field: "json_duplicate"}
				}
				seen[s] = true
				if e = value(depth + 1); e != nil {
					return e
				}
			}
			end, e := d.Token()
			if e != nil || end != json.Delim('}') {
				return Invalid{Field: "json"}
			}
		case '[':
			for d.More() {
				if e = value(depth + 1); e != nil {
					return e
				}
			}
			end, e := d.Token()
			if e != nil || end != json.Delim(']') {
				return Invalid{Field: "json"}
			}
		default:
			return Invalid{Field: "json"}
		}
		return nil
	}
	if e := value(0); e != nil {
		return e
	}
	if _, e := d.Token(); e != io.EOF {
		return Invalid{Field: "json_trailing"}
	}
	return nil
}
func decodeBase64(s string, maximum int) ([]byte, error) {
	if len(s) == 0 || len(s) > base64.RawURLEncoding.EncodedLen(maximum) {
		return nil, Invalid{Field: "base64url"}
	}
	v, e := base64.RawURLEncoding.Strict().DecodeString(s)
	if e != nil || len(v) > maximum || base64.RawURLEncoding.EncodeToString(v) != s {
		return nil, Invalid{Field: "base64url"}
	}
	return v, nil
}

type browserResponse struct {
	ID       string `json:"id"`
	RawID    string `json:"rawId"`
	Type     string `json:"type"`
	Response struct {
		ClientDataJSON    string  `json:"clientDataJSON"`
		AttestationObject string  `json:"attestationObject"`
		AuthenticatorData string  `json:"authenticatorData"`
		Signature         string  `json:"signature"`
		UserHandle        *string `json:"userHandle"`
	} `json:"response"`
	Extensions map[string]json.RawMessage `json:"clientExtensionResults"`
}
type clientData struct {
	Type        string          `json:"type"`
	Challenge   string          `json:"challenge"`
	Origin      string          `json:"origin"`
	CrossOrigin bool            `json:"crossOrigin"`
	TopOrigin   json.RawMessage `json:"topOrigin"`
}

func parseResponse(wire []byte) (browserResponse, []byte, []byte, error) {
	var r browserResponse
	if e := validateJSON(wire, 128<<10); e != nil {
		return r, nil, nil, e
	}
	if json.Unmarshal(wire, &r) != nil || r.Type != "public-key" {
		return r, nil, nil, Invalid{Field: "response"}
	}
	id, e := decodeBase64(r.RawID, 1024)
	if e != nil {
		return r, nil, nil, e
	}
	other, e := decodeBase64(r.ID, 1024)
	if e != nil || !bytes.Equal(id, other) {
		return r, nil, nil, Invalid{Field: "credential_id"}
	}
	client, e := decodeBase64(r.Response.ClientDataJSON, 16<<10)
	if e != nil {
		return r, nil, nil, e
	}
	return r, id, client, nil
}
