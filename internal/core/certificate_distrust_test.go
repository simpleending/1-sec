package core

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"testing"
	"time"
)

// GO-2026-6809: distrust follows the public key, including certificates issued
// under a different trusted root. Public SPKIs come from rustls/webpki PR #546:
// https://github.com/rustls/webpki/pull/546 (restore the outer DER sequence).
func TestCertificateDistrust(t *testing.T) {
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "regression root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, signer.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	issue := func(publicKey crypto.PublicKey) *x509.Certificate {
		t.Helper()
		template := &x509.Certificate{
			SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "nats.example"},
			DNSNames: []string{"nats.example"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		der, err := x509.CreateCertificate(rand.Reader, template, root, publicKey, signer)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		if err := cert.CheckSignatureFrom(root); err != nil {
			t.Fatal(err)
		}
		return cert
	}
	options := x509.VerifyOptions{Roots: roots, DNSName: "nats.example", CurrentTime: now}
	t.Run("trusted ordinary key", func(t *testing.T) {
		if _, err := issue(signer.Public()).Verify(options); err != nil {
			t.Fatalf("valid certificate rejected: %v", err)
		}
	})
	for _, test := range []struct{ name, spki string }{
		{"EMDVTLSCAG3B", "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE557ZwEqXc8RzXlERHahawr1eZKs3S4DhLLwgOOweTw47gS/JhZ4eZ6+wTi+LyX90hbplqpEe6KTkW2LVzAPVa+Z4s8OMtNyTfKJGDiOEU8iSk10p1E+R4VYGtjzO2rRo"},
		{"EMDVTLSCAG3C", "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEOnp4YsjETTJN3WkDOmeCwO/u/kBV5ooSP6A3G6O9kZRRTuFypDPjYw8CvRiAN9nlFJ+bd9uUooHfmHsv6oiLdL3+j9pMEJnubKGVZv4+8OX2sJpVbMyLpQVh3xsqRB0B"},
		{"EMEVTLSCAG3B", "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEJduoWmTTl9oLEFLp6lRuSHvv6pydnWigxerc/u91ppu11vwB9Cv7ym60C81kwHZ+Nv/QXZeoE8WqDGyVMOec9fCGZGjxOAZCCqXIUYQLHiUlQOeQ5LZUw4Uu1krx6GV9"},
		{"EMEVTLSCAG3C", "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAELVboKab7gsZKRpfZYK+VHpBnrpH5JtNDBtpIqKrreGm2pn5tJ0JuBEKqA7NuGYjf9jZRTuHPB/W6Sz/yoGZFrn0x1YZq0xqj0kbrCzF37pnLdWbFFs50gIpmj5HwxH/K"},
		{"EMOVCSCAG3B", "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEqrsPsGZqz88B+tUr/P1MK/LLPDSX3nOVDlgZth/mlQmHQcjEkUObNKBDHK/+W/m0wcjorgAB+fTcitgsWfNjnpbNbD1NsM7+wmw9YlF7N3YTcnQ/jordd7EAZPKr5eBQ"},
		{"EMOVCSCAG3C", "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEufDgY0cCppymqt1EPP1ixBubpLIJJGl9eXTnaRoSb7lq+z40wv07xfSDBh8mXcKlhDY0cyNRBDayjwTzhiNjBnmA4lA+AlMtZUYjWnFlolmh70lvdBtf3ud4cgjkuPrv"},
		{"EMOVTLSCAG3B", "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEc4l6oOs8/cqLEkAv+vCrxOEhK6+N7neKye4tbbg/rCgMXgVjiueirNccMiqONhzeufacQwK53Y1z0cxsqrLMCu5OIWzped1Rikr0tiblaEzdZYA37QyFTkzBL0z4ZG0N"},
		{"EMOVTLSCAG3C", "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEE4JRzVKskpjByKrZdzId65fnCb0LTKCspV3IrVHc/J0ViaFZfjpRIOHv1jHGPhg1ysrimGmmLhYx6KKBgatWYW3EXZGKvAnzqw5jz3kqpNztc4e+N7ulaVSfHAKycO1n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			der, err := base64.StdEncoding.DecodeString(test.spki)
			if err != nil {
				t.Fatal(err)
			}
			publicKey, err := x509.ParsePKIXPublicKey(der)
			if err != nil {
				t.Fatal(err)
			}
			_, err = issue(publicKey).Verify(options)
			var invalid x509.CertificateInvalidError
			if !errors.As(err, &invalid) || invalid.Reason != x509.NoValidChains {
				t.Fatalf("distrusted key accepted or wrong failure: %v", err)
			}
		})
	}
}
