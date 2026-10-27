package office

import (
	"archive/zip"
	"bytes"
	"fmt"
	"time"
)

// Blank documents for "New document / spreadsheet / presentation". They're
// built here rather than copied from the Document Server's own templates:
// the smallest valid Office Open XML packages, which the editor fills in
// with its defaults when they're first opened. The integration test opens
// each one in a real Document Server.

// Kinds of new document.
const (
	KindDocument     = "document"
	KindSpreadsheet  = "spreadsheet"
	KindPresentation = "presentation"
)

// NewKinds maps a kind to the extension its files get.
var NewKinds = map[string]string{
	KindDocument:     "docx",
	KindSpreadsheet:  "xlsx",
	KindPresentation: "pptx",
}

const xmlHead = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` + "\n"

const relsNS = `http://schemas.openxmlformats.org/package/2006/relationships`
const relOffice = `http://schemas.openxmlformats.org/officeDocument/2006/relationships`

// Blank returns an empty file of kind ("document", "spreadsheet" or
// "presentation").
func Blank(kind string) ([]byte, error) {
	var parts [][2]string
	switch kind {
	case KindDocument:
		parts = blankDocx
	case KindSpreadsheet:
		parts = blankXlsx
	case KindPresentation:
		parts = blankPptx
	default:
		return nil, fmt.Errorf("unknown kind %q", kind)
	}
	var buf bytes.Buffer
	z := zip.NewWriter(&buf)
	// A fixed time keeps the bytes the same every time.
	mod := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, p := range parts {
		w, err := z.CreateHeader(&zip.FileHeader{Name: p[0], Method: zip.Deflate, Modified: mod})
		if err != nil {
			return nil, err
		}
		if _, err := w.Write([]byte(xmlHead + p[1])); err != nil {
			return nil, err
		}
	}
	if err := z.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

var blankDocx = [][2]string{
	{"[Content_Types].xml", `<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
		`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
		`<Default Extension="xml" ContentType="application/xml"/>` +
		`<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>` +
		`</Types>`},
	{"_rels/.rels", `<Relationships xmlns="` + relsNS + `">` +
		`<Relationship Id="rId1" Type="` + relOffice + `/officeDocument" Target="word/document.xml"/></Relationships>`},
	{"word/document.xml", `<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">` +
		`<w:body><w:p/><w:sectPr><w:pgSz w:w="11906" w:h="16838"/>` +
		`<w:pgMar w:top="1134" w:right="850" w:bottom="1134" w:left="1701" w:header="709" w:footer="709" w:gutter="0"/></w:sectPr></w:body></w:document>`},
}

var blankXlsx = [][2]string{
	{"[Content_Types].xml", `<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
		`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
		`<Default Extension="xml" ContentType="application/xml"/>` +
		`<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>` +
		`<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>` +
		`</Types>`},
	{"_rels/.rels", `<Relationships xmlns="` + relsNS + `">` +
		`<Relationship Id="rId1" Type="` + relOffice + `/officeDocument" Target="xl/workbook.xml"/></Relationships>`},
	{"xl/workbook.xml", `<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="` + relOffice + `">` +
		`<sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets></workbook>`},
	{"xl/_rels/workbook.xml.rels", `<Relationships xmlns="` + relsNS + `">` +
		`<Relationship Id="rId1" Type="` + relOffice + `/worksheet" Target="worksheets/sheet1.xml"/></Relationships>`},
	{"xl/worksheets/sheet1.xml", `<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData/></worksheet>`},
}

const nsA = `http://schemas.openxmlformats.org/drawingml/2006/main`
const nsP = `http://schemas.openxmlformats.org/presentationml/2006/main`

const pptNS = `xmlns:a="` + nsA + `" xmlns:r="` + relOffice + `" xmlns:p="` + nsP + `"`

const emptyTree = `<p:cSld><p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>` +
	`<p:grpSpPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/><a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/></a:xfrm></p:grpSpPr>` +
	`</p:spTree></p:cSld>`

const sysClr = `<a:dk1><a:srgbClr val="000000"/></a:dk1><a:lt1><a:srgbClr val="FFFFFF"/></a:lt1>` +
	`<a:dk2><a:srgbClr val="1F2937"/></a:dk2><a:lt2><a:srgbClr val="E5E7EB"/></a:lt2>` +
	`<a:accent1><a:srgbClr val="22D3EE"/></a:accent1><a:accent2><a:srgbClr val="8B5CFF"/></a:accent2>` +
	`<a:accent3><a:srgbClr val="0E9F75"/></a:accent3><a:accent4><a:srgbClr val="E08A12"/></a:accent4>` +
	`<a:accent5><a:srgbClr val="2F6BFF"/></a:accent5><a:accent6><a:srgbClr val="D9475A"/></a:accent6>` +
	`<a:hlink><a:srgbClr val="2F6BFF"/></a:hlink><a:folHlink><a:srgbClr val="7C5CF5"/></a:folHlink>`

const solid = `<a:solidFill><a:schemeClr val="phClr"/></a:solidFill>`
const line = `<a:ln w="9525">` + solid + `</a:ln>`

var blankPptx = [][2]string{
	{"[Content_Types].xml", `<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
		`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
		`<Default Extension="xml" ContentType="application/xml"/>` +
		`<Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/>` +
		`<Override PartName="/ppt/slideMasters/slideMaster1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slideMaster+xml"/>` +
		`<Override PartName="/ppt/slideLayouts/slideLayout1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slideLayout+xml"/>` +
		`<Override PartName="/ppt/slides/slide1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slide+xml"/>` +
		`<Override PartName="/ppt/theme/theme1.xml" ContentType="application/vnd.openxmlformats-officedocument.theme+xml"/>` +
		`</Types>`},
	{"_rels/.rels", `<Relationships xmlns="` + relsNS + `">` +
		`<Relationship Id="rId1" Type="` + relOffice + `/officeDocument" Target="ppt/presentation.xml"/></Relationships>`},
	{"ppt/presentation.xml", `<p:presentation ` + pptNS + `>` +
		`<p:sldMasterIdLst><p:sldMasterId id="2147483648" r:id="rId1"/></p:sldMasterIdLst>` +
		`<p:sldIdLst><p:sldId id="256" r:id="rId2"/></p:sldIdLst>` +
		`<p:sldSz cx="12192000" cy="6858000"/><p:notesSz cx="6858000" cy="9144000"/></p:presentation>`},
	{"ppt/_rels/presentation.xml.rels", `<Relationships xmlns="` + relsNS + `">` +
		`<Relationship Id="rId1" Type="` + relOffice + `/slideMaster" Target="slideMasters/slideMaster1.xml"/>` +
		`<Relationship Id="rId2" Type="` + relOffice + `/slide" Target="slides/slide1.xml"/>` +
		`<Relationship Id="rId3" Type="` + relOffice + `/theme" Target="theme/theme1.xml"/></Relationships>`},
	{"ppt/slideMasters/slideMaster1.xml", `<p:sldMaster ` + pptNS + `>` + emptyTree +
		`<p:clrMap bg1="lt1" tx1="dk1" bg2="lt2" tx2="dk2" accent1="accent1" accent2="accent2" accent3="accent3" accent4="accent4" accent5="accent5" accent6="accent6" hlink="hlink" folHlink="folHlink"/>` +
		`<p:sldLayoutIdLst><p:sldLayoutId id="2147483649" r:id="rId1"/></p:sldLayoutIdLst></p:sldMaster>`},
	{"ppt/slideMasters/_rels/slideMaster1.xml.rels", `<Relationships xmlns="` + relsNS + `">` +
		`<Relationship Id="rId1" Type="` + relOffice + `/slideLayout" Target="../slideLayouts/slideLayout1.xml"/>` +
		`<Relationship Id="rId2" Type="` + relOffice + `/theme" Target="../theme/theme1.xml"/></Relationships>`},
	{"ppt/slideLayouts/slideLayout1.xml", `<p:sldLayout ` + pptNS + ` type="blank" preserve="1">` + emptyTree +
		`<p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr></p:sldLayout>`},
	{"ppt/slideLayouts/_rels/slideLayout1.xml.rels", `<Relationships xmlns="` + relsNS + `">` +
		`<Relationship Id="rId1" Type="` + relOffice + `/slideMaster" Target="../slideMasters/slideMaster1.xml"/></Relationships>`},
	{"ppt/slides/slide1.xml", `<p:sld ` + pptNS + `>` + emptyTree +
		`<p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr></p:sld>`},
	{"ppt/slides/_rels/slide1.xml.rels", `<Relationships xmlns="` + relsNS + `">` +
		`<Relationship Id="rId1" Type="` + relOffice + `/slideLayout" Target="../slideLayouts/slideLayout1.xml"/></Relationships>`},
	{"ppt/theme/theme1.xml", `<a:theme xmlns:a="` + nsA + `" name="HardyOS"><a:themeElements>` +
		`<a:clrScheme name="HardyOS">` + sysClr + `</a:clrScheme>` +
		`<a:fontScheme name="HardyOS"><a:majorFont><a:latin typeface="Arial"/><a:ea typeface=""/><a:cs typeface=""/></a:majorFont>` +
		`<a:minorFont><a:latin typeface="Arial"/><a:ea typeface=""/><a:cs typeface=""/></a:minorFont></a:fontScheme>` +
		`<a:fmtScheme name="HardyOS">` +
		`<a:fillStyleLst>` + solid + solid + solid + `</a:fillStyleLst>` +
		`<a:lnStyleLst>` + line + line + line + `</a:lnStyleLst>` +
		`<a:effectStyleLst><a:effectStyle><a:effectLst/></a:effectStyle><a:effectStyle><a:effectLst/></a:effectStyle><a:effectStyle><a:effectLst/></a:effectStyle></a:effectStyleLst>` +
		`<a:bgFillStyleLst>` + solid + solid + solid + `</a:bgFillStyleLst>` +
		`</a:fmtScheme></a:themeElements></a:theme>`},
}
