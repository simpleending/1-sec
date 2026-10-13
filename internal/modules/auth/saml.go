package auth

import (
	"encoding/base64"
	"encoding/xml"
	"io"
	"net/url"
	"strings"

	"github.com/1sec-project/1sec/internal/core"
)

const (
	samlProtocolNS  = "urn:oasis:names:tc:SAML:2.0:protocol"
	samlAssertionNS = "urn:oasis:names:tc:SAML:2.0:assertion"
	samlSignatureNS = "http://www.w3.org/2000/09/xmldsig#"
	maxSAMLBytes    = 1 << 20
)

func (f *Fortress) handleSAMLResponse(event *core.SecurityEvent) {
	raw := getStringDetail(event, "saml_response")
	if raw == "" {
		raw = getStringDetail(event, "body")
	}
	if raw == "" {
		return
	}
	if reason := inspectSAMLResponse(raw); reason != "" {
		f.raiseAlert(event, core.SeverityHigh, "Suspicious SAML Response Structure", reason, "saml_structure_violation")
	}
}

// Inspect structure only; signature authenticity and claim validation belong to the IdP/SP verifier.
// Ref: https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html
func inspectSAMLResponse(raw string) string {
	if len(raw) > 2*maxSAMLBytes {
		return "SAML input exceeds the inspection limit"
	}
	raw = strings.TrimSpace(strings.TrimPrefix(raw, "\ufeff"))
	if !strings.HasPrefix(raw, "<") && strings.Contains(raw, "SAMLResponse=") {
		values, err := url.ParseQuery(raw)
		if err != nil || len(values["SAMLResponse"]) != 1 {
			return "Malformed or ambiguous SAMLResponse form field"
		}
		raw = values.Get("SAMLResponse")
	}
	if !strings.HasPrefix(raw, "<") {
		decoded, err := base64.StdEncoding.Strict().DecodeString(raw)
		if err != nil {
			return "SAML response is neither XML nor valid base64"
		}
		raw = string(decoded)
	}
	if len(raw) > maxSAMLBytes {
		return "Decoded SAML response exceeds the inspection limit"
	}

	type element struct {
		name xml.Name
		id   string
	}
	type signature struct {
		parentID                string
		signedInfos, references int
	}
	var stack []element
	var currentSignature *signature
	var responseID string
	var assertionIDs []string
	ids, signed := make(map[string]bool), make(map[string]bool)
	rootSeen := false
	nodes := 0
	decoder := xml.NewDecoder(strings.NewReader(strings.TrimPrefix(raw, "\ufeff")))
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "Malformed SAML XML"
		}
		switch tok := token.(type) {
		case xml.Directive:
			return "DTD and other XML directives are not permitted in SAML responses"
		case xml.ProcInst:
			if tok.Target != "xml" || rootSeen {
				return "Unexpected processing instruction in SAML XML"
			}
		case xml.CharData:
			if len(stack) == 0 && strings.TrimSpace(string(tok)) != "" {
				return "Unexpected data outside the SAML Response"
			}
		case xml.StartElement:
			nodes++
			if nodes > 8192 || len(stack) >= 64 || len(tok.Attr) > 128 {
				return "SAML XML exceeds element, depth, or attribute limits"
			}
			id := ""
			attrs := make(map[xml.Name]bool)
			for _, attr := range tok.Attr {
				if attrs[attr.Name] {
					return "Duplicate XML attributes in SAML response"
				}
				attrs[attr.Name] = true
				if attr.Name.Local == "ID" || attr.Name.Local == "Id" || attr.Name.Local == "id" {
					if id != "" || attr.Value == "" || ids[attr.Value] {
						return "Duplicate or ambiguous XML IDs in SAML response"
					}
					id = attr.Value
					ids[id] = true
				}
			}
			var parent element
			if len(stack) > 0 {
				parent = stack[len(stack)-1]
			} else {
				if rootSeen || tok.Name != (xml.Name{Space: samlProtocolNS, Local: "Response"}) {
					return "Expected a single SAML 2.0 Response root"
				}
				rootSeen = true
				responseID = id
			}
			switch tok.Name.Local {
			case "Response":
				if tok.Name.Space != samlProtocolNS || len(stack) != 0 || samlAttr(tok, "ID") == "" {
					return "Unexpected or unidentified SAML Response"
				}
			case "Assertion", "EncryptedAssertion":
				if tok.Name.Space != samlAssertionNS || len(stack) != 1 || parent.name.Local != "Response" {
					return "SAML assertion is outside the expected Response position or namespace"
				}
				if tok.Name.Local == "Assertion" {
					if samlAttr(tok, "ID") == "" {
						return "SAML Assertion has no unambiguous ID"
					}
					assertionIDs = append(assertionIDs, id)
				}
			case "Signature":
				if tok.Name.Space != samlSignatureNS || currentSignature != nil ||
					(parent.name.Local != "Response" && parent.name.Local != "Assertion") || signed[parent.id] {
					return "XML signature is outside the expected SAML signed element"
				}
				currentSignature = &signature{parentID: parent.id}
			case "SignedInfo":
				if tok.Name.Space != samlSignatureNS || currentSignature == nil || parent.name != (xml.Name{Space: samlSignatureNS, Local: "Signature"}) {
					return "Misplaced XML SignedInfo"
				}
				currentSignature.signedInfos++
			case "Reference":
				if tok.Name.Space != samlSignatureNS || currentSignature == nil || parent.name != (xml.Name{Space: samlSignatureNS, Local: "SignedInfo"}) ||
					samlAttr(tok, "URI") != "#"+currentSignature.parentID {
					return "XML signature reference does not bind to its enclosing Response or Assertion"
				}
				currentSignature.references++
			case "Transform":
				algorithm := samlAttr(tok, "Algorithm")
				if currentSignature != nil && algorithm != samlSignatureNS+"enveloped-signature" &&
					algorithm != "http://www.w3.org/2001/10/xml-exc-c14n#" && algorithm != "http://www.w3.org/2001/10/xml-exc-c14n#WithComments" {
					return "Unsupported XML signature transform may exclude authentication claims"
				}
			}
			stack = append(stack, element{name: tok.Name, id: id})
		case xml.EndElement:
			if tok.Name == (xml.Name{Space: samlSignatureNS, Local: "Signature"}) && currentSignature != nil {
				if currentSignature.signedInfos != 1 || currentSignature.references != 1 {
					return "SAML signature must have exactly one SignedInfo and one reference"
				}
				signed[currentSignature.parentID] = true
				currentSignature = nil
			}
			stack = stack[:len(stack)-1]
		}
	}
	if !rootSeen || len(stack) != 0 {
		return "Incomplete SAML Response"
	}
	if !signed[responseID] {
		for _, id := range assertionIDs {
			if !signed[id] {
				return "SAML assertion is outside signed Response or Assertion content"
			}
		}
	}
	// Encrypted assertions remain opaque; the service provider must decrypt and verify them.
	return ""
}

func samlAttr(element xml.StartElement, name string) string {
	for _, attr := range element.Attr {
		if attr.Name.Space == "" && attr.Name.Local == name {
			return attr.Value
		}
	}
	return ""
}
