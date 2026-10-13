package auth

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/1sec-project/1sec/internal/core"
)

func samlTestResponse(content string) string {
	return fmt.Sprintf(`<p:Response xmlns:p="%s" xmlns:a="%s" xmlns:ds="%s" ID="response">%s</p:Response>`, samlProtocolNS, samlAssertionNS, samlSignatureNS, content)
}

func samlTestSignature(id string) string {
	return `<ds:Signature><ds:SignedInfo><ds:Reference URI="#` + id + `"/></ds:SignedInfo><ds:SignatureValue>fixture</ds:SignatureValue></ds:Signature>`
}

func TestInspectSAMLResponse_Structure(t *testing.T) {
	assertion := `<a:Assertion ID="assertion"><a:Subject><a:NameID>user</a:NameID></a:Subject></a:Assertion>`
	signedResponse := samlTestResponse(samlTestSignature("response") + assertion)
	for _, tt := range []struct {
		name, input string
		violation   bool
	}{
		{"response signature", signedResponse, false},
		{"UTF-8 BOM response", "\ufeff" + signedResponse, false},
		{"base64 UTF-8 BOM", base64.StdEncoding.EncodeToString([]byte("\ufeff" + signedResponse)), false},
		{"assertion signature", samlTestResponse(`<a:Assertion ID="assertion">` + samlTestSignature("assertion") + `</a:Assertion>`), false},
		{"base64 response", base64.StdEncoding.EncodeToString([]byte(signedResponse)), false},
		{"form response", "SAMLResponse=" + url.QueryEscape(base64.StdEncoding.EncodeToString([]byte(signedResponse))), false},
		{"form response after RelayState", "RelayState=state&SAMLResponse=" + url.QueryEscape(base64.StdEncoding.EncodeToString([]byte(signedResponse))), false},
		{"enveloped signature transform", strings.Replace(signedResponse, `URI="#response"/>`, `URI="#response"><ds:Transforms><ds:Transform Algorithm="`+samlSignatureNS+`enveloped-signature"/></ds:Transforms></ds:Reference>`, 1), false},
		{"encrypted assertion opaque", samlTestResponse(`<a:EncryptedAssertion/>`), false},
		{"error response without assertions", samlTestResponse(`<p:Status/>`), false},
		{"unsigned assertion", samlTestResponse(assertion), true},
		{"duplicate IDs", samlTestResponse(samlTestSignature("response") + `<a:Assertion ID="response"/>`), true},
		{"ambiguous ID attributes", strings.Replace(signedResponse, `ID="response"`, `ID="response" xml:id="alternate"`, 1), true},
		{"duplicate attributes", strings.Replace(signedResponse, `ID="response"`, `ID="response" ID="alternate"`, 1), true},
		{"wrong reference target", samlTestResponse(samlTestSignature("other") + assertion), true},
		{"external reference", strings.Replace(signedResponse, `URI="#response"`, `URI="https://attacker.example/signed"`, 1), true},
		{"empty reference", strings.Replace(signedResponse, `URI="#response"`, `URI=""`, 1), true},
		{"nested assertion", samlTestResponse(samlTestSignature("response") + `<p:Extensions>` + assertion + `</p:Extensions>`), true},
		{"spoofed assertion namespace", strings.Replace(signedResponse, samlAssertionNS, "urn:attacker", 1), true},
		{"misplaced signature", samlTestResponse(`<p:Extensions>` + samlTestSignature("response") + `</p:Extensions>` + assertion), true},
		{"unsigned sibling assertion", samlTestResponse(`<a:Assertion ID="first">` + samlTestSignature("first") + `</a:Assertion>` + assertion), true},
		{"duplicate signature", samlTestResponse(samlTestSignature("response") + samlTestSignature("response") + assertion), true},
		{"missing reference", samlTestResponse(`<ds:Signature><ds:SignedInfo/></ds:Signature>` + assertion), true},
		{"multiple references", strings.Replace(signedResponse, `</ds:SignedInfo>`, `<ds:Reference URI="#response"/></ds:SignedInfo>`, 1), true},
		{"claim-excluding transform", strings.Replace(signedResponse, `URI="#response"/>`, `URI="#response"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"/></ds:Transforms></ds:Reference>`, 1), true},
		{"doctype", `<!DOCTYPE p:Response [<!ENTITY external SYSTEM "https://attacker.example/">]>` + signedResponse, true},
		{"processing instruction", `<?attack data?>` + signedResponse, true},
		{"malformed XML", signedResponse[:len(signedResponse)-1], true},
		{"multiple roots", signedResponse + signedResponse, true},
		{"trailing text", signedResponse + "extra", true},
		{"invalid base64", "invalid!", true},
		{"duplicate form fields", "SAMLResponse=a&SAMLResponse=b", true},
		{"empty input", "", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if reason := inspectSAMLResponse(tt.input); (reason != "") != tt.violation {
				t.Fatalf("violation = %v, want %v: %s", reason != "", tt.violation, reason)
			}
		})
	}
}

func TestInspectSAMLResponse_Bounded(t *testing.T) {
	var attributes strings.Builder
	for i := 0; i < 129; i++ {
		fmt.Fprintf(&attributes, ` a%d="x"`, i)
	}
	for _, tt := range []struct{ name, input string }{
		{"raw size", strings.Repeat(" ", 2*maxSAMLBytes+1)},
		{"decoded size", base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", maxSAMLBytes+1)))},
		{"depth", samlTestResponse(strings.Repeat("<x>", 65) + strings.Repeat("</x>", 65))},
		{"elements", samlTestResponse(strings.Repeat("<x/>", 8193))},
		{"attributes", samlTestResponse("<x" + attributes.String() + "/>")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if reason := inspectSAMLResponse(tt.input); reason == "" {
				t.Fatal("oversized SAML input was accepted")
			}
		})
	}
}

func TestFortress_SAMLResponseEmitsAlert(t *testing.T) {
	cp := makeCapturingPipeline()
	f := startedModuleWithPipeline(t, cp)
	defer f.Stop()
	if !slices.Contains(f.EventTypes(), "saml_response") {
		t.Fatal("SAML events are not subscribed")
	}
	if schema, ok := core.EventSchemaMap()["saml_response"]; !ok || !slices.Contains(schema.OptionalKeys, "saml_response") {
		t.Fatal("SAML telemetry is not documented in the canonical event contract")
	}
	event := core.NewSecurityEvent("test", "saml_response", core.SeverityInfo, "SAML login")
	event.Details["body"] = samlTestResponse(`<a:Assertion ID="unsigned"/>`)
	f.HandleEvent(event)
	if !cp.hasAlertType("saml_structure_violation") {
		t.Fatal("SAML event did not emit a structural violation alert")
	}
	if len(getAuthMitigations("saml_structure_violation")) == 0 {
		t.Fatal("SAML alert has no mitigation guidance")
	}
}
