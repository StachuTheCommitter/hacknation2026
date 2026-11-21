// Package dd: klient REST API v2 DefectDojo (import-scan, reimport-scan, findings, system_settings).
package dd

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Client struct {
	URL   string
	Token string
	HTTP  *http.Client
}

func New(baseURL, token string, insecure bool) *Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return &Client{URL: strings.TrimRight(baseURL, "/"), Token: token, HTTP: &http.Client{Timeout: 60 * time.Second, Transport: tr}}
}

// Finding – format Generic Findings Import.
type Finding struct {
	Title            string     `json:"title"`
	Severity         string     `json:"severity"`
	Description      string     `json:"description"`
	UniqueIDFromTool string     `json:"unique_id_from_tool"`
	VulnIDFromTool   string     `json:"vuln_id_from_tool,omitempty"`
	ComponentName    string     `json:"component_name,omitempty"`
	ComponentVersion string     `json:"component_version,omitempty"`
	References       string     `json:"references,omitempty"`
	Endpoints        []Endpoint `json:"endpoints,omitempty"`
	Tags             []string   `json:"tags,omitempty"`
	StaticFinding    bool       `json:"static_finding"`
	DynamicFinding   bool       `json:"dynamic_finding"`
	FalsePositive    bool       `json:"false_p,omitempty"`
}

type Endpoint struct {
	Protocol string `json:"protocol,omitempty"`
	Host     string `json:"host"`
	Port     int    `json:"port,omitempty"`
	Path     string `json:"path,omitempty"`
}

type APIError struct {
	Status int
	Body   string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("DefectDojo HTTP %d: %s", e.Status, truncate(e.Body, 400))
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

func (c *Client) do(ctx context.Context, method, path string, body io.Reader, ctype string, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, c.URL+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Token "+c.Token)
	req.Header.Set("Accept", "application/json")
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if resp.StatusCode >= 300 {
		return &APIError{resp.StatusCode, string(b)}
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}

// Info – wynik testu połączenia.
type Info struct {
	OK            bool   `json:"ok"`
	User          string `json:"user"`
	Deduplication *bool  `json:"deduplication"`
	Message       string `json:"message"`
}

func (c *Client) Test(ctx context.Context) Info {
	var users struct {
		Results []struct {
			Username string `json:"username"`
		} `json:"results"`
	}
	if err := c.do(ctx, "GET", "/api/v2/users/?limit=1", nil, "", &users); err != nil {
		return Info{Message: err.Error()}
	}
	info := Info{OK: true}
	if len(users.Results) > 0 {
		info.User = users.Results[0].Username
	}
	var ss struct {
		Results []struct {
			EnableDeduplication bool `json:"enable_deduplication"`
		} `json:"results"`
	}
	if err := c.do(ctx, "GET", "/api/v2/system_settings/", nil, "", &ss); err == nil && len(ss.Results) > 0 {
		d := ss.Results[0].EnableDeduplication
		info.Deduplication = &d
		if !d {
			info.Message = "Deduplikacja w DefectDojo jest wyłączona (System Settings → Deduplicate findings)."
		}
	}
	return info
}

type ImportParams struct {
	ScanType    string
	ProductType string
	Product     string
	Engagement  string
	TestTitle   string
	TestID      int
	CloseOld    bool
	FileName    string
	File        []byte
}

// Import wykonuje import-scan (TestID==0) albo reimport-scan i zwraca id testu.
func (c *Client) Import(ctx context.Context, p ImportParams) (int, map[string]any, error) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	field := func(k, v string) { w.WriteField(k, v) }
	field("scan_type", p.ScanType)
	field("minimum_severity", "Info")
	field("active", "true")
	field("verified", "false")
	field("close_old_findings", strconv.FormatBool(p.CloseOld))
	field("scan_date", time.Now().Format("2006-01-02"))
	path := "/api/v2/import-scan/"
	if p.TestID > 0 {
		path = "/api/v2/reimport-scan/"
		field("test", strconv.Itoa(p.TestID))
		field("do_not_reactivate", "false")
	} else {
		field("auto_create_context", "true")
		field("product_type_name", p.ProductType)
		field("product_name", p.Product)
		field("engagement_name", p.Engagement)
		field("test_title", p.TestTitle)
		field("deduplication_on_engagement", "true")
	}
	fw, _ := w.CreateFormFile("file", p.FileName)
	fw.Write(p.File)
	w.Close()
	var out map[string]any
	if err := c.do(ctx, "POST", path, &buf, w.FormDataContentType(), &out); err != nil {
		return 0, nil, err
	}
	id := 0
	for _, k := range []string{"test_id", "test"} {
		switch v := out[k].(type) {
		case float64:
			id = int(v)
		case string:
			id, _ = strconv.Atoi(v)
		}
		if id > 0 {
			break
		}
	}
	if id == 0 {
		id = p.TestID
	}
	return id, out, nil
}

// RemoteFinding – status znaleziska po stronie DefectDojo.
type RemoteFinding struct {
	ID               int    `json:"id"`
	Title            string `json:"title"`
	UniqueIDFromTool string `json:"unique_id_from_tool"`
	Active           bool   `json:"active"`
	FalseP           bool   `json:"false_p"`
	RiskAccepted     bool   `json:"risk_accepted"`
	IsMitigated      bool   `json:"is_mitigated"`
	OutOfScope       bool   `json:"out_of_scope"`
	Duplicate        bool   `json:"duplicate"`
}

func (f RemoteFinding) Status() string {
	switch {
	case f.FalseP:
		return "false_positive"
	case f.RiskAccepted:
		return "risk_accepted"
	case f.OutOfScope:
		return "out_of_scope"
	case f.IsMitigated:
		return "mitigated"
	case f.Duplicate:
		return "duplicate"
	}
	return "open"
}

func (c *Client) Findings(ctx context.Context, testID int) ([]RemoteFinding, error) {
	var all []RemoteFinding
	next := fmt.Sprintf("/api/v2/findings/?test=%d&limit=500", testID)
	for next != "" {
		var page struct {
			Next    *string         `json:"next"`
			Results []RemoteFinding `json:"results"`
		}
		if err := c.do(ctx, "GET", next, nil, "", &page); err != nil {
			return nil, err
		}
		all = append(all, page.Results...)
		next = ""
		if page.Next != nil && *page.Next != "" {
			if u, err := url.Parse(*page.Next); err == nil {
				next = u.RequestURI()
			}
		}
	}
	return all, nil
}

func (c *Client) Patch(ctx context.Context, id int, fields map[string]any) error {
	b, _ := json.Marshal(fields)
	return c.do(ctx, "PATCH", fmt.Sprintf("/api/v2/findings/%d/", id), bytes.NewReader(b), "application/json", nil)
}
