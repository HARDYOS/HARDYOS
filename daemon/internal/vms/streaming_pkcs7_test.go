package vms

import (
	"archive/zip"
	"bytes"
	"crypto/sha1" //nolint:gosec // Windows certificate thumbprints are SHA-1
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"os"
	"strings"
	"testing"
)

// catalogSigner returns the Windows thumbprint (upper-case SHA-1 of the
// DER certificate) of the signer of the .cat file in a driver zip.
func catalogSigner(zipBytes []byte) (string, error) {
	zr, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		return "", err
	}
	for _, f := range zr.File {
		if !strings.HasSuffix(strings.ToLower(f.Name), ".cat") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return "", err
		}
		b, err := io.ReadAll(io.LimitReader(rc, 8<<20))
		rc.Close()
		if err != nil {
			return "", err
		}
		return pkcs7Signer(b)
	}
	return "", errors.New("no .cat file in the zip")
}

type p7ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

type p7SignedData struct {
	Version      int
	DigestAlgs   asn1.RawValue
	Encap        asn1.RawValue
	Certificates asn1.RawValue  `asn1:"optional,tag:0"`
	CRLs         asn1.RawValue  `asn1:"optional,tag:1"`
	SignerInfos  []p7SignerInfo `asn1:"set"`
}

type p7SignerInfo struct {
	Version     int
	SID         asn1.RawValue
	DigestAlg   asn1.RawValue
	AuthAttrs   asn1.RawValue `asn1:"optional,tag:0"`
	SigAlg      asn1.RawValue
	Signature   []byte
	UnauthAttrs asn1.RawValue `asn1:"optional,tag:1"`
}

type p7IssuerSerial struct {
	Issuer asn1.RawValue
	Serial *big.Int
}

func pkcs7Signer(der []byte) (string, error) {
	var ci p7ContentInfo
	if _, err := asn1.Unmarshal(der, &ci); err != nil {
		return "", err
	}
	var sd p7SignedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return "", err
	}
	var certs []*x509.Certificate
	rest := sd.Certificates.Bytes
	for len(rest) > 0 {
		var raw asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &raw); err != nil {
			return "", err
		}
		if c, err := x509.ParseCertificate(raw.FullBytes); err == nil {
			certs = append(certs, c)
		}
	}
	if len(sd.SignerInfos) == 0 {
		return "", errors.New("no signer")
	}
	sid := sd.SignerInfos[0].SID
	for _, c := range certs {
		match := false
		if sid.Class == asn1.ClassContextSpecific && sid.Tag == 0 {
			match = bytes.Equal(sid.Bytes, c.SubjectKeyId)
		} else {
			var is p7IssuerSerial
			if _, err := asn1.Unmarshal(sid.FullBytes, &is); err == nil {
				match = bytes.Equal(is.Issuer.FullBytes, c.RawIssuer) && is.Serial.Cmp(c.SerialNumber) == 0
			}
		}
		if match {
			sum := sha1.Sum(c.Raw) //nolint:gosec // a thumbprint, not a security check by itself
			return strings.ToUpper(hex.EncodeToString(sum[:])), nil
		}
	}
	return "", errors.New("the signer's certificate isn't in the catalog")
}

// The fixture is a zip with a .cat signed (openssl smime) by a throwaway
// self-signed certificate whose SHA-1 fingerprint is below.
func TestCatalogSigner(t *testing.T) {
	b, err := os.ReadFile("testdata/streaming/signed-catalog.zip")
	if err != nil {
		t.Fatal(err)
	}
	got, err := catalogSigner(b)
	if err != nil || got != "D43A37CDBD8B1418C21DCCAC96C5A55CF145AC74" {
		t.Fatalf("signer %q %v", got, err)
	}
	if _, err := catalogSigner([]byte("not a zip")); err == nil {
		t.Fatal("not a zip")
	}
}
