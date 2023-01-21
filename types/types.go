package types

type Scan struct {
	ID              string                   `json:"scan_id,omitempty"`
	Domain          string                   `json:"domain,omitempty"`
	Date            string                   `json:"date,omitempty"`
	Status          Status                   `json:"status,omitempty"`
	SubDomains      []string                 `json:"-"`
	Vulnerabilities map[string]Vulnerability `json:"-"`
}

type Vulnerability struct {
	IP     string
	Report []string
}

type Status string

const (
	Queued   Status = "queued"
	Ongoing  Status = "ongoing"
	Finished Status = "finished"
	Error    Status = "error"
)
