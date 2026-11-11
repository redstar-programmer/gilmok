package main

// Bulk service registration from a spreadsheet (.xlsx or CSV).
//
//   GET  /api/services/export.xlsx            current services (edit and upload again)
//   GET  /api/services/export.xlsx?template=1 empty form + 안내 sheet
//   POST /api/services/bulk {name, data(base64), dry}
//        dry=true  → preview: per row create / update / delete / same / error
//        dry=false → apply every valid row in one store update (error rows are skipped)
//
// A blank cell keeps the current value (update) or uses the default (new service); "-" clears a
// text cell. The 삭제 column (Y) removes the service. Nothing touches Caddy until 「적용」.

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/csv"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const bulkMaxRows = 2000

type bulkCol struct {
	key     string
	title   string
	aliases []string
	choices []string // Excel dropdown
	width   int
	help    string
}

var bulkCols = []bulkCol{
	{"subdomain", "서브도메인", []string{"subdomain", "sub", "이름", "호스트"}, nil, 18, "필수. 예: photos → photos.<도메인>, 루트 도메인은 @"},
	{"upstream", "대상", []string{"upstream", "target", "대상(host:port)"}, nil, 26, "host:port (예: immich_server:2283). DNS만이면 비움"},
	{"exposure", "노출", []string{"exposure", "공개여부"}, []string{"공개", "사설"}, 9, "공개(:443) 또는 사설(Tailscale 등 :8443). 새 서비스 기본: 공개"},
	{"enabled", "사용", []string{"enabled", "enable"}, []string{"Y", "N"}, 7, "N이면 Caddyfile에 만들지 않음. 새 서비스 기본: Y"},
	{"proxied", "Proxied", []string{"proxied", "proxy", "cloudflare프록시", "구름"}, []string{"Y", "N"}, 9, "Cloudflare Proxied(Y) / DNS only(N). 공개 서비스만"},
	{"mtls", "mTLS", []string{"mtls", "cf_only"}, []string{"Y", "N"}, 7, "Cloudflare 경유만 허용(인증된 원본 풀). Proxied일 때만"},
	{"manageDns", "DNS 관리", []string{"managedns", "dns관리", "dns"}, []string{"Y", "N"}, 9, "Cloudflare DNS 레코드를 길목이 맞춤. 새 서비스 기본: Y(Cloudflare 사용 시)"},
	{"dnsOnly", "DNS만", []string{"dnsonly", "dns only", "dns전용"}, []string{"Y", "N"}, 8, "Y = Caddy 사이트 없이 DNS 레코드만"},
	{"authelia", "Authelia", []string{"authelia", "인증", "로그인"}, []string{"끔", "1단계", "2단계"}, 10, "Authelia 로그인 관문. 1단계=비밀번호, 2단계=비밀번호+OTP"},
	{"groups", "허용 그룹", []string{"groups", "group", "그룹"}, nil, 16, "쉼표로 구분 (예: admins, family). 길목에 등록된 그룹만 — 「안내」 시트 아래 목록 참고. 비우면 로그인한 누구나"},
	{"waf", "WAF", []string{"waf", "coraza"}, []string{"끔", "탐지", "차단"}, 8, "Caddy WAF(OWASP CRS). 탐지=기록만, 차단=403"},
	{"guard", "기본 차단", []string{"guard", "봇차단"}, []string{"Y", "N"}, 10, "알려진 공격 도구·경로·AI 크롤러 차단"},
	{"notes", "메모", []string{"notes", "note", "설명", "비고"}, nil, 24, "Caddyfile 주석으로 기록"},
	{"extra", "추가 지시어", []string{"extra", "지시어", "caddy"}, nil, 30, "reverse_proxy 앞에 넣을 Caddy 지시어. 여러 줄 가능(셀 안 줄바꿈)"},
	{"delete", "삭제", []string{"delete", "remove", "삭제여부"}, []string{"Y"}, 7, "Y면 이 서비스를 삭제"},
}

func normHeader(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if i := strings.IndexAny(s, "(（"); i > 0 {
		s = s[:i]
	}
	return strings.NewReplacer(" ", "", "*", "", "_", "", "-", "", " ", "").Replace(s)
}

func bulkColumnOf(header string) string {
	n := normHeader(header)
	if n == "" {
		return ""
	}
	for _, c := range bulkCols {
		if normHeader(c.title) == n || strings.EqualFold(c.key, n) {
			return c.key
		}
		for _, a := range c.aliases {
			if normHeader(a) == n {
				return c.key
			}
		}
	}
	return ""
}

// ---------------------------------------------------------------- reading

func readSheet(name string, data []byte) ([][]string, error) {
	if bytes.HasPrefix(data, []byte("PK")) {
		return readXLSX(data)
	}
	if strings.HasSuffix(strings.ToLower(name), ".xls") {
		return nil, errors.New("예전 .xls 형식은 읽을 수 없습니다 — 엑셀에서 「다른 이름으로 저장 › Excel 통합 문서(.xlsx)」로 저장해 올리세요")
	}
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	if !utf8.Valid(data) {
		return nil, errors.New("CSV가 UTF-8이 아닙니다 — 엑셀에서 「CSV UTF-8(쉼표로 분리)」로 저장하거나 .xlsx 파일을 올리세요")
	}
	r := csv.NewReader(bytes.NewReader(data))
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	first, _, _ := strings.Cut(string(data), "\n")
	if strings.Count(first, ";") > strings.Count(first, ",") {
		r.Comma = ';'
	} else if strings.Count(first, "\t") > strings.Count(first, ",") {
		r.Comma = '\t'
	}
	rows, err := r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("CSV를 읽지 못했습니다: %v", err)
	}
	return rows, nil
}

type xlRels struct {
	Rel []struct {
		ID     string `xml:"Id,attr"`
		Target string `xml:"Target,attr"`
	} `xml:"Relationship"`
}

type xlRun struct {
	T string `xml:"t"`
}

type xlStr struct {
	T string  `xml:"t"`
	R []xlRun `xml:"r"`
}

func (s xlStr) text() string {
	if len(s.R) == 0 {
		return s.T
	}
	var b strings.Builder
	for _, r := range s.R {
		b.WriteString(r.T)
	}
	return b.String()
}

var reCellRef = regexp.MustCompile(`^([A-Z]+)(\d+)$`)

func colIndex(letters string) int {
	n := 0
	for _, c := range letters {
		n = n*26 + int(c-'A'+1)
	}
	return n - 1
}

func readXLSX(data []byte) ([][]string, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, errors.New("엑셀 파일(.xlsx)을 열 수 없습니다 — 파일이 손상됐거나 암호가 걸려 있습니다")
	}
	files := map[string]*zip.File{}
	for _, f := range zr.File {
		files[strings.TrimPrefix(f.Name, "/")] = f
	}
	read := func(name string, max int64) ([]byte, error) {
		f := files[name]
		if f == nil {
			return nil, fmt.Errorf("%s 없음", name)
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		defer rc.Close()
		b, err := io.ReadAll(io.LimitReader(rc, max+1))
		if int64(len(b)) > max {
			return nil, errors.New("엑셀 파일 내용이 너무 큽니다")
		}
		return b, err
	}
	// first sheet: workbook.xml → relationship → worksheet path
	sheetPath := "xl/worksheets/sheet1.xml"
	if wb, err := read("xl/workbook.xml", 4<<20); err == nil {
		var w struct {
			Sheets []struct {
				RID string `xml:"http://schemas.openxmlformats.org/officeDocument/2006/relationships id,attr"`
			} `xml:"sheets>sheet"`
		}
		if xml.Unmarshal(wb, &w) == nil && len(w.Sheets) > 0 {
			if rb, err := read("xl/_rels/workbook.xml.rels", 1<<20); err == nil {
				var rels xlRels
				if xml.Unmarshal(rb, &rels) == nil {
					for _, r := range rels.Rel {
						if r.ID == w.Sheets[0].RID {
							t := r.Target
							if strings.HasPrefix(t, "/") {
								sheetPath = strings.TrimPrefix(t, "/")
							} else {
								sheetPath = path.Clean("xl/" + t)
							}
						}
					}
				}
			}
		}
	}
	var shared []string
	if sb, err := read("xl/sharedStrings.xml", 32<<20); err == nil {
		var sst struct {
			SI []xlStr `xml:"si"`
		}
		if err := xml.Unmarshal(sb, &sst); err != nil {
			return nil, fmt.Errorf("엑셀 문자열 표를 읽지 못했습니다: %v", err)
		}
		for _, si := range sst.SI {
			shared = append(shared, si.text())
		}
	}
	sb, err := read(sheetPath, 64<<20)
	if err != nil {
		return nil, fmt.Errorf("엑셀 시트를 찾지 못했습니다: %v", err)
	}
	var ws struct {
		Rows []struct {
			R     int `xml:"r,attr"`
			Cells []struct {
				R  string `xml:"r,attr"`
				T  string `xml:"t,attr"`
				V  string `xml:"v"`
				Is xlStr  `xml:"is"`
			} `xml:"c"`
		} `xml:"sheetData>row"`
	}
	if err := xml.Unmarshal(sb, &ws); err != nil {
		return nil, fmt.Errorf("엑셀 시트를 읽지 못했습니다: %v", err)
	}
	var out [][]string
	for i, row := range ws.Rows {
		ri := row.R - 1
		if row.R == 0 {
			ri = i
		}
		if ri >= bulkMaxRows+50 {
			return nil, fmt.Errorf("행이 너무 많습니다 (최대 %d행)", bulkMaxRows)
		}
		for len(out) <= ri {
			out = append(out, nil)
		}
		var cells []string
		for j, c := range row.Cells {
			ci := j
			if m := reCellRef.FindStringSubmatch(c.R); m != nil {
				ci = colIndex(m[1])
			}
			if ci < 0 || ci > 200 {
				continue
			}
			v := c.V
			switch c.T {
			case "s":
				if k, err := strconv.Atoi(strings.TrimSpace(c.V)); err == nil && k >= 0 && k < len(shared) {
					v = shared[k]
				}
			case "inlineStr":
				v = c.Is.text()
			case "b":
				v = map[string]string{"1": "Y", "0": "N"}[strings.TrimSpace(c.V)]
			}
			for len(cells) <= ci {
				cells = append(cells, "")
			}
			cells[ci] = v
		}
		out[ri] = cells
	}
	return out, nil
}

// ---------------------------------------------------------------- planning

type BulkRow struct {
	Row       int      `json:"row"` // spreadsheet row number (1-based, header = 1)
	Subdomain string   `json:"subdomain"`
	Action    string   `json:"action"` // create | update | delete | same | error
	Changes   []string `json:"changes,omitempty"`
	Error     string   `json:"error,omitempty"`
}

type BulkPlan struct {
	Rows    []BulkRow      `json:"rows"`
	Counts  map[string]int `json:"counts"`
	Columns []string       `json:"columns"` // recognised columns (titles)
	Ignored []string       `json:"ignored,omitempty"`
}

func yesNo(v string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "y", "yes", "o", "true", "1", "예", "사용", "켬", "on", "✓", "v":
		return true, nil
	case "n", "no", "x", "false", "0", "아니오", "아니요", "안 함", "끔", "off", "-":
		return false, nil
	}
	return false, fmt.Errorf("%q 는 Y 또는 N 이어야 합니다", v)
}

var bulkFieldTitle = func() map[string]string {
	m := map[string]string{}
	for _, c := range bulkCols {
		m[c.key] = c.title
	}
	return m
}()

// applyBulkCell changes one field of s from a cell; "" means keep.
func applyBulkCell(s *Service, key, v string, st Settings) error {
	v = strings.TrimSpace(strings.ReplaceAll(v, "\r\n", "\n"))
	if v == "" {
		return nil
	}
	clear := v == "-"
	setBool := func(p *bool) error {
		b, err := yesNo(v)
		if err == nil {
			*p = b
		}
		return err
	}
	switch key {
	case "subdomain":
		s.Subdomain = strings.ToLower(v)
		if d := strings.ToLower(st.Domain); d != "" {
			if s.Subdomain == d {
				s.Subdomain = "@"
			} else {
				s.Subdomain = strings.TrimSuffix(s.Subdomain, "."+d)
			}
		}
	case "upstream":
		if clear {
			s.Upstream = ""
		} else {
			s.Upstream = v
		}
	case "exposure":
		switch strings.ToLower(v) {
		case "공개", "public", "외부", "인터넷":
			s.Exposure = ExposurePublic
		case "사설", "tailscale", "private", "내부", "ts", "vpn":
			s.Exposure = ExposureTailscale
		default:
			return fmt.Errorf("노출 %q 는 공개 또는 사설이어야 합니다", v)
		}
	case "enabled":
		return setBool(&s.Enabled)
	case "proxied":
		switch strings.ToLower(v) {
		case "proxied", "주황":
			s.Proxied = true
			return nil
		case "dns only", "dnsonly", "회색":
			s.Proxied = false
			return nil
		}
		return setBool(&s.Proxied)
	case "mtls":
		return setBool(&s.MTLS)
	case "manageDns":
		return setBool(&s.ManageDNS)
	case "dnsOnly":
		return setBool(&s.DNSOnly)
	case "authelia":
		switch strings.ToLower(strings.ReplaceAll(v, " ", "")) {
		case "끔", "n", "no", "off", "-", "없음", "bypass", "false", "0":
			s.Authelia.Enabled = false
		case "1단계", "one_factor", "onefactor", "1", "1fa", "비밀번호":
			s.Authelia.Enabled, s.Authelia.Policy = true, "one_factor"
		case "2단계", "two_factor", "twofactor", "2", "2fa", "y", "yes", "켬", "on":
			s.Authelia.Enabled, s.Authelia.Policy = true, "two_factor"
		default:
			return fmt.Errorf("Authelia %q 는 끔 / 1단계 / 2단계 중 하나여야 합니다", v)
		}
	case "groups":
		s.Authelia.Groups = []string{}
		if !clear {
			for _, g := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ';' || r == '\n' || r == ' ' }) {
				if g = strings.TrimSpace(g); g != "" {
					if !validUsername(g) {
						return fmt.Errorf("그룹 이름 %q 에는 영문/숫자/-_. 만 쓸 수 있습니다", g)
					}
					s.Authelia.Groups = append(s.Authelia.Groups, g)
				}
			}
		}
	case "waf":
		switch strings.ToLower(v) {
		case "끔", "n", "no", "off", "-", "없음":
			s.WAF = WAFOff
		case "탐지", "detect", "기록":
			s.WAF = WAFDetect
		case "차단", "block", "y", "on":
			s.WAF = WAFBlock
		default:
			return fmt.Errorf("WAF %q 는 끔 / 탐지 / 차단 중 하나여야 합니다", v)
		}
	case "guard":
		return setBool(&s.Guard)
	case "notes":
		if clear {
			s.Notes = ""
		} else {
			s.Notes = strings.ReplaceAll(v, "\n", " ")
		}
	case "extra":
		if clear {
			s.Extra = ""
		} else {
			s.Extra = v
		}
	}
	return nil
}

func serviceFieldsDiff(a, b *Service) []string {
	var out []string
	add := func(cond bool, key string) {
		if cond {
			out = append(out, bulkFieldTitle[key])
		}
	}
	add(a.Subdomain != b.Subdomain, "subdomain")
	add(a.Upstream != b.Upstream, "upstream")
	add(a.Exposure != b.Exposure, "exposure")
	add(a.Enabled != b.Enabled, "enabled")
	add(a.Proxied != b.Proxied, "proxied")
	add(a.MTLS != b.MTLS, "mtls")
	add(a.ManageDNS != b.ManageDNS, "manageDns")
	add(a.DNSOnly != b.DNSOnly, "dnsOnly")
	add(a.Authelia.Enabled != b.Authelia.Enabled || (a.Authelia.Enabled && a.Authelia.Policy != b.Authelia.Policy), "authelia")
	add(strings.Join(a.Authelia.Groups, ",") != strings.Join(b.Authelia.Groups, ","), "groups")
	add(a.WAF != b.WAF, "waf")
	add(a.Guard != b.Guard, "guard")
	add(a.Notes != b.Notes, "notes")
	add(strings.TrimRight(a.Extra, "\n ") != strings.TrimRight(b.Extra, "\n "), "extra")
	return out
}

// planBulk works on a copy of the service list; with apply it also returns the new list.
// known: registered Authelia groups (nil = do not check).
func planBulk(rows [][]string, cur []*Service, st Settings, known map[string]bool) (BulkPlan, []*Service, []string, error) {
	plan := BulkPlan{Counts: map[string]int{}}
	// header = first non-empty row
	hi := -1
	for i, r := range rows {
		if strings.TrimSpace(strings.Join(r, "")) != "" {
			hi = i
			break
		}
	}
	if hi < 0 {
		return plan, nil, nil, errors.New("파일이 비어 있습니다")
	}
	colKey := map[int]string{}
	seen := map[string]bool{}
	for j, hcell := range rows[hi] {
		k := bulkColumnOf(hcell)
		if k == "" || seen[k] {
			if strings.TrimSpace(hcell) != "" {
				plan.Ignored = append(plan.Ignored, strings.TrimSpace(hcell))
			}
			continue
		}
		seen[k] = true
		colKey[j] = k
		plan.Columns = append(plan.Columns, bulkFieldTitle[k])
	}
	if !seen["subdomain"] {
		return plan, nil, nil, errors.New("첫 줄(제목 행)에 「서브도메인」 열이 없습니다 — 길목에서 받은 양식을 쓰거나 제목 행을 맞춰 주세요")
	}
	if len(rows)-hi-1 > bulkMaxRows {
		return plan, nil, nil, fmt.Errorf("행이 너무 많습니다 (최대 %d행)", bulkMaxRows)
	}

	// working copy
	work := make([]*Service, 0, len(cur))
	bySub := map[string]*Service{}
	for _, s := range cur {
		c := *s
		c.Authelia.Groups = append([]string{}, s.Authelia.Groups...)
		work = append(work, &c)
		bySub[c.Subdomain] = &c
	}
	orig := map[string]*Service{}
	for _, s := range cur {
		orig[s.ID] = s
	}
	inFile := map[string]int{}
	var dirty []string
	now := time.Now()

	for i := hi + 1; i < len(rows); i++ {
		r := rows[i]
		cell := map[string]string{}
		for j, v := range r {
			if k, ok := colKey[j]; ok {
				cell[k] = v
			}
		}
		if strings.TrimSpace(strings.Join(r, "")) == "" || strings.HasPrefix(strings.TrimSpace(cell["subdomain"]), "#") {
			continue
		}
		row := BulkRow{Row: i + 1}
		bad := func(err error) {
			row.Action, row.Error = "error", err.Error()
			plan.Rows = append(plan.Rows, row)
			plan.Counts["error"]++
		}
		// subdomain (normalised) decides create vs update
		probe := Service{}
		if err := applyBulkCell(&probe, "subdomain", cell["subdomain"], st); err != nil {
			bad(err)
			continue
		}
		sub := probe.Subdomain
		row.Subdomain = sub
		if sub == "" {
			bad(errors.New("서브도메인이 비어 있습니다"))
			continue
		}
		if prev, dup := inFile[sub]; dup {
			bad(fmt.Errorf("파일 안에서 %d행과 서브도메인이 겹칩니다", prev))
			continue
		}
		inFile[sub] = i + 1
		existing := bySub[sub]

		if del := strings.TrimSpace(cell["delete"]); del != "" {
			yes, err := yesNo(del)
			if err != nil {
				bad(fmt.Errorf("삭제: %v", err))
				continue
			}
			if yes {
				if existing == nil {
					bad(errors.New("삭제할 서비스가 없습니다 (등록되지 않은 서브도메인)"))
					continue
				}
				for k, s := range work {
					if s == existing {
						work = append(work[:k], work[k+1:]...)
						break
					}
				}
				delete(bySub, sub)
				row.Action = "delete"
				plan.Rows = append(plan.Rows, row)
				plan.Counts["delete"]++
				dirty = append(dirty, "서비스 삭제 (엑셀): "+st.FQDN(sub))
				continue
			}
		}

		var s Service
		if existing != nil {
			s = *existing
			s.Authelia.Groups = append([]string{}, existing.Authelia.Groups...)
		} else {
			s = Service{Exposure: ExposurePublic, Enabled: true, ManageDNS: st.UseCloudflare, Authelia: AutheliaOpts{Policy: "two_factor", Groups: []string{}}}
		}
		var cellErr error
		for _, c := range bulkCols {
			if c.key == "subdomain" || c.key == "delete" {
				continue
			}
			if err := applyBulkCell(&s, c.key, cell[c.key], st); err != nil {
				cellErr = fmt.Errorf("%s: %v", c.title, err)
				break
			}
		}
		if cellErr != nil {
			bad(cellErr)
			continue
		}
		s.Subdomain = sub
		if known != nil {
			var before []string
			if existing != nil {
				before = orig[existing.ID].Authelia.Groups
			}
			if err := checkNewGroups(known, before, s.Authelia.Groups); err != nil {
				bad(fmt.Errorf("허용 그룹: %v", err))
				continue
			}
		}
		if err := validateService(&s, work, st); err != nil {
			bad(err)
			continue
		}
		if existing == nil {
			s.ID, s.Updated = newID(), now
			ns := s
			work = append(work, &ns)
			bySub[sub] = &ns
			row.Action = "create"
			dirty = append(dirty, "서비스 추가 (엑셀): "+st.FQDN(sub))
		} else {
			o := orig[existing.ID]
			if o == nil {
				o = existing
			}
			row.Changes = serviceFieldsDiff(o, &s)
			if len(row.Changes) == 0 {
				row.Action = "same"
			} else {
				row.Action = "update"
				s.Updated = now
				dirty = append(dirty, "서비스 수정 (엑셀): "+st.FQDN(sub))
			}
			*existing = s
		}
		plan.Rows = append(plan.Rows, row)
		plan.Counts[row.Action]++
	}
	if len(plan.Rows) == 0 {
		return plan, nil, nil, errors.New("서비스 행이 없습니다 — 제목 행 아래에 한 줄에 서비스 하나씩 적어 주세요")
	}
	return plan, work, dirty, nil
}

// ---------------------------------------------------------------- handlers

func (a *App) postServicesBulk(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name string `json:"name"`
		Data string `json:"data"`
		Dry  bool   `json:"dry"`
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, 400, errors.New("파일이 너무 큽니다 (최대 약 1.4 MB)"))
		return
	}
	raw, err := base64.StdEncoding.DecodeString(in.Data)
	if err != nil || len(raw) == 0 {
		fail(w, 400, errors.New("파일을 읽지 못했습니다"))
		return
	}
	rows, err := readSheet(in.Name, raw)
	if err != nil {
		fail(w, 400, err)
		return
	}
	if in.Dry {
		d := a.store.Snapshot()
		plan, _, _, err := planBulk(rows, d.Services, d.Settings, d.groupSet())
		if err != nil {
			writeJSON(w, 400, map[string]any{"error": err.Error(), "plan": plan})
			return
		}
		writeJSON(w, 200, plan)
		return
	}
	var plan BulkPlan
	err = a.store.Update(func(d *Data) error {
		p, work, dirty, err := planBulk(rows, d.Services, d.Settings, d.groupSet())
		plan = p
		if err != nil {
			return err
		}
		if len(dirty) == 0 {
			return nil
		}
		d.Services = work
		for _, m := range dirty {
			d.markDirty(m)
		}
		return nil
	})
	if err != nil {
		a.auth.audit(r, "audit", "error", "서비스 일괄 등록 (엑셀)", truncate(in.Name, 80), "서비스 일괄 등록 — 실패: "+truncate(err.Error(), 300), nil)
		writeJSON(w, 400, map[string]any{"error": err.Error(), "plan": plan})
		return
	}
	a.detectSelf()
	c := plan.Counts
	var subs []string
	for _, x := range plan.Rows {
		if x.Action != "same" && x.Action != "error" {
			subs = append(subs, x.Action+" "+x.Subdomain)
		}
	}
	a.auth.audit(r, "audit", "warn", "서비스 일괄 등록 (엑셀)", truncate(in.Name, 80),
		fmt.Sprintf("서비스 일괄 등록 — 추가 %d · 수정 %d · 삭제 %d · 그대로 %d · 오류 %d (건너뜀)", c["create"], c["update"], c["delete"], c["same"], c["error"]),
		map[string]any{"rows": subs})
	writeJSON(w, 200, plan)
}

func (a *App) getServicesExport(w http.ResponseWriter, r *http.Request) {
	d := a.store.Snapshot()
	template := r.URL.Query().Get("template") == "1"
	var rows [][]string
	if !template {
		list := append([]*Service{}, d.Services...)
		sort.SliceStable(list, func(i, j int) bool {
			if list[i].Exposure != list[j].Exposure {
				return list[i].Exposure == ExposurePublic
			}
			return list[i].Subdomain < list[j].Subdomain
		})
		for _, s := range list {
			rows = append(rows, serviceRow(s))
		}
	}
	b, err := writeServicesXLSX(rows, d.Settings, d.AGroups)
	if err != nil {
		fail(w, 500, err)
		return
	}
	name := "gilmok-services-" + time.Now().Format("20060102") + ".xlsx"
	if template {
		name = "gilmok-services-template.xlsx"
	}
	w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(b)
}

func serviceRow(s *Service) []string {
	yn := func(b bool) string {
		if b {
			return "Y"
		}
		return "N"
	}
	exp := "공개"
	if s.Exposure != ExposurePublic {
		exp = "사설"
	}
	auth := "끔"
	if s.Authelia.Enabled {
		auth = map[string]string{"one_factor": "1단계"}[s.Authelia.Policy]
		if auth == "" {
			auth = "2단계"
		}
	}
	waf := map[string]string{WAFDetect: "탐지", WAFBlock: "차단"}[s.WAF]
	if waf == "" {
		waf = "끔"
	}
	m := map[string]string{
		"subdomain": s.Subdomain, "upstream": s.Upstream, "exposure": exp, "enabled": yn(s.Enabled),
		"proxied": yn(s.Proxied), "mtls": yn(s.MTLS), "manageDns": yn(s.ManageDNS), "dnsOnly": yn(s.DNSOnly),
		"authelia": auth, "groups": strings.Join(s.Authelia.Groups, ", "), "waf": waf, "guard": yn(s.Guard),
		"notes": s.Notes, "extra": s.Extra, "delete": "",
	}
	out := make([]string, len(bulkCols))
	for i, c := range bulkCols {
		out[i] = m[c.key]
	}
	return out
}

// ---------------------------------------------------------------- writing (minimal SpreadsheetML)

func xmlEsc(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

func colName(i int) string {
	s := ""
	for i++; i > 0; i = (i - 1) / 26 {
		s = string(rune('A'+(i-1)%26)) + s
	}
	return s
}

func sheetXML(header []string, rows [][]string, widths []int, validations []string, freeze bool) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` + "\n")
	b.WriteString(`<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">`)
	if freeze {
		b.WriteString(`<sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews>`)
	}
	b.WriteString(`<cols>`)
	for i, wd := range widths {
		fmt.Fprintf(&b, `<col min="%d" max="%d" width="%d" customWidth="1"/>`, i+1, i+1, wd)
	}
	b.WriteString(`</cols><sheetData>`)
	writeRow := func(n int, cells []string, style int) {
		fmt.Fprintf(&b, `<row r="%d">`, n)
		for j, v := range cells {
			if v == "" {
				continue
			}
			st := ""
			if style > 0 {
				st = fmt.Sprintf(` s="%d"`, style)
			} else if strings.Contains(v, "\n") {
				st = ` s="2"`
			}
			fmt.Fprintf(&b, `<c r="%s%d" t="inlineStr"%s><is><t xml:space="preserve">%s</t></is></c>`, colName(j), n, st, xmlEsc(v))
		}
		b.WriteString(`</row>`)
	}
	writeRow(1, header, 1)
	for i, r := range rows {
		writeRow(i+2, r, 0)
	}
	b.WriteString(`</sheetData>`)
	if len(validations) > 0 {
		fmt.Fprintf(&b, `<dataValidations count="%d">%s</dataValidations>`, len(validations), strings.Join(validations, ""))
	}
	b.WriteString(`</worksheet>`)
	return b.String()
}

func writeServicesXLSX(rows [][]string, st Settings, groups []AGroup) ([]byte, error) {
	header := make([]string, len(bulkCols))
	widths := make([]int, len(bulkCols))
	var vals []string
	last := max(len(rows)+1, 1) + 500
	for i, c := range bulkCols {
		header[i] = c.title
		widths[i] = c.width
		if len(c.choices) > 0 {
			vals = append(vals, fmt.Sprintf(`<dataValidation type="list" allowBlank="1" showErrorMessage="1" errorTitle="%s" error="%s" sqref="%s2:%s%d"><formula1>"%s"</formula1></dataValidation>`,
				xmlEsc(c.title), xmlEsc(strings.Join(c.choices, " / ")+" 중에서 고르세요"), colName(i), colName(i), last, xmlEsc(strings.Join(c.choices, ","))))
		}
	}
	dom := st.Domain
	if dom == "" {
		dom = "example.com"
	}
	guide := [][]string{}
	for _, c := range bulkCols {
		ch := strings.Join(c.choices, " / ")
		guide = append(guide, []string{c.title, ch, c.help})
	}
	guide = append(guide, []string{}, []string{"규칙", "", "한 줄에 서비스 하나. 서브도메인이 이미 있으면 수정, 없으면 추가합니다."},
		[]string{"", "", "빈 칸 = 지금 값 그대로(새 서비스는 기본값). 글자 칸을 지우려면 - 를 입력하세요."},
		[]string{"", "", "서브도메인이 # 으로 시작하는 줄은 건너뜁니다. 주소 전체(" + "photos." + dom + ")를 적어도 됩니다."},
		[]string{"", "", "올리면 먼저 미리보기가 나오고, 반영해도 「적용」 전까지 Caddy·DNS는 바뀌지 않습니다."},
	)
	var gl []string
	for _, g := range groups {
		if g.Desc != "" {
			gl = append(gl, g.Name+" ("+g.Desc+")")
		} else {
			gl = append(gl, g.Name)
		}
	}
	if len(gl) == 0 {
		gl = []string{"(아직 없음 — Authelia 탭 › 사용자 · 그룹 › 그룹에서 추가)"}
	}
	guide = append(guide, []string{"등록된 그룹", "", strings.Join(gl, ", ")}, []string{}, []string{"예시", "", ""})
	guide = append(guide, append([]string{}, header...))
	guide = append(guide,
		[]string{"photos", "immich_server:2283", "공개", "Y", "N", "N", "Y", "N", "끔", "", "탐지", "Y", "사진", "", ""},
		[]string{"admin", "dockhand:3000", "사설", "Y", "", "", "Y", "N", "2단계", "admins", "차단", "Y", "관리 화면", "", ""},
		[]string{"old", "", "", "", "", "", "", "", "", "", "", "", "", "", "Y"},
	)
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	put := func(name, body string) error {
		f, err := zw.Create(name)
		if err != nil {
			return err
		}
		_, err = io.WriteString(f, body)
		return err
	}
	parts := []struct{ name, body string }{
		{"[Content_Types].xml", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/><Override PartName="/xl/worksheets/sheet2.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/></Types>`},
		{"_rels/.rels", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>`},
		{"xl/workbook.xml", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="서비스" sheetId="1" r:id="rId1"/><sheet name="안내" sheetId="2" r:id="rId2"/></sheets></workbook>`},
		{"xl/_rels/workbook.xml.rels", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet2.xml"/><Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>`},
		{"xl/styles.xml", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><fonts count="2"><font><sz val="11"/><name val="맑은 고딕"/><family val="3"/></font><font><b/><sz val="11"/><name val="맑은 고딕"/><family val="3"/></font></fonts><fills count="3"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill><fill><patternFill patternType="solid"><fgColor rgb="FFDDE3F0"/><bgColor indexed="64"/></patternFill></fill></fills><borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs><cellXfs count="3"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1"/><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf></cellXfs><cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles></styleSheet>`},
		{"xl/worksheets/sheet1.xml", sheetXML(header, rows, widths, vals, true)},
		{"xl/worksheets/sheet2.xml", sheetXML([]string{"열", "고를 수 있는 값", "설명"}, guide, []int{14, 18, 90}, nil, false)},
	}
	for _, p := range parts {
		if err := put(p.name, p.body); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
