// Lookup Forked From https://github.com/emersion/go-msgauth/tree/master/dmarc, With More RFC Oriented.

package lookup

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

type AlignmentMode string

const (
	AlignmentStrict  AlignmentMode = "s"
	AlignmentRelaxed AlignmentMode = "r"
)

type FailureOptions int

const (
	FailureAll  FailureOptions = 1 << iota // "0"
	FailureAny                             // "1"
	FailureDKIM                            // "d"
	FailureSPF                             // "s"
)

type Policy string

const (
	PolicyNone       Policy = "none"
	PolicyQuarantine        = "quarantine"
	PolicyReject            = "reject"
)

type ReportFormat string

const (
	ReportFormatAFRF ReportFormat = "afrf"
	ReportFormatIODEF ReportFormat = "iodef"
)

// Record is a DMARC record, as defined in RFC 7489 section 6.3.
type Record struct {
	DKIMAlignment      AlignmentMode  // "adkim"
	SPFAlignment       AlignmentMode  // "aspf"
	FailureOptions     FailureOptions // "fo"
	Policy             Policy         // "p"
	Percent            *int           // "pct"
	ReportFormat       []ReportFormat // "rf"
	ReportInterval     time.Duration  // "ri"
	ReportURIAggregate []string       // "rua"
	ReportURIFailure   []string       // "ruf"
	SubdomainPolicy    Policy         // "sp"
}

const (
	// According to RFC , DMARC Record should be started with v=
	RFCDmarcRecordPrefix = "v=DMARC1"
)

var RFCSupportedTags = map[string]struct{}{
    "v":     {},
    "p":     {},
    "adkim": {},
    "aspf":  {},
    "fo":    {},
    "pct":   {},
    "rf":    {},
    "ri":    {},
    "rua":   {},
    "ruf":   {},
    "sp":    {},
}

type tempFailError string

func (err tempFailError) Error() string {
	return "dmarc: " + string(err)
}

// IsTempFail returns true if the error returned by Lookup is a temporary
// failure.
func IsTempFail(err error) bool {
	_, ok := err.(tempFailError)
	return ok
}

var ErrNoPolicy = errors.New("dmarc: no policy found for domain")
var ErrMultipleRecords = errors.New("dmarc: multiple DMARC records found for domain")

// LookupOptions allows to customize the default signature verification behavior
// LookupTXT returns the DNS TXT records for the given domain name. If nil, net.LookupTXT is used
type LookupOptions struct {
	LookupTXT func(domain string) ([]string, error)
}

// Lookup queries a DMARC record for a specified domain.
func Lookup(domain string) (*Record, error) {
	return LookupWithOptions(domain, nil)
}

func LookupWithOptions(domain string, options *LookupOptions) (*Record, error) {
	var txts []string
	var dmarcRecords []Record
	var err error
	if options != nil && options.LookupTXT != nil {
		txts, err = options.LookupTXT("_dmarc." + domain)
	} else {
		txts, err = net.LookupTXT("_dmarc." + domain)
	}

	if err != nil {
		if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
			return nil, ErrNoPolicy
		}
		return nil, errors.New("dmarc: failed to lookup TXT record: " + err.Error())
	}

	if len(txts) == 0 {
		return nil, ErrNoPolicy
	}

	for _, txt := range txts {
		if strings.HasPrefix(txt, RFCDmarcRecordPrefix) {
			record, err := Parse(txt)
			if err == nil {
				dmarcRecords = append(dmarcRecords, *record)
			} else {
				return nil, err
			}
		}
	}

	if len(dmarcRecords) == 0 {
		return nil, ErrNoPolicy
	} else if len(dmarcRecords) > 1 {
		return nil, ErrMultipleRecords
	} else {
		return &dmarcRecords[0], nil
	}
}

func Parse(txt string) (*Record, error) {
	params, err := parseParams(txt)
	if err != nil {
		return nil, err
	}

	if !strings.EqualFold(params["v"], "DMARC1") {
		return nil, errors.New("dmarc: unsupported DMARC version")
	}

	rec := new(Record)

	p, ok := params["p"]
	if !ok {
		return nil, errors.New("dmarc: record is missing a 'p' parameter")
	}
	rec.Policy, err = parsePolicy(p, "p")
	if err != nil {
		return nil, err
	}

	rec.DKIMAlignment = AlignmentRelaxed
	if adkim, ok := params["adkim"]; ok {
		rec.DKIMAlignment, err = parseAlignmentMode(adkim, "adkim")
		if err != nil {
			return nil, err
		}
	}

	rec.SPFAlignment = AlignmentRelaxed
	if aspf, ok := params["aspf"]; ok {
		rec.SPFAlignment, err = parseAlignmentMode(aspf, "aspf")
		if err != nil {
			return nil, err
		}
	}

	if fo, ok := params["fo"]; ok {
		rec.FailureOptions, _ = parseFailureOptions(fo)
	}

	if pct, ok := params["pct"]; ok {
		i, err := strconv.Atoi(pct)

		if err != nil {
			// Defaults to 100 according to RFC in case of syntax errors.
			i = 100
		}

		if i < 0 || i > 100 {
			return nil, fmt.Errorf("dmarc: invalid parameter 'pct': value %v out of bounds", i)
		}
		rec.Percent = &i
	}

	if rf, ok := params["rf"]; ok {
		l := strings.Split(rf, ":")
		rec.ReportFormat = make([]ReportFormat, len(l))
		for i, f := range l {
			switch f {
			case "afrf":
				rec.ReportFormat[i] = ReportFormat(f)
			case "iodef":
				// Even though its not part of RFC,  still some people use it.
				rec.ReportFormat[i] = ReportFormat(f)
			default:
				return nil, errors.New("dmarc: invalid parameter 'rf'")
			}
		}
	}

	if ri, ok := params["ri"]; ok {
		i, err := strconv.Atoi(ri)

		if err != nil {
			// Defaults to 86400 according to RFC in case of syntax errors.
			i = 86400
		}

		if i <= 0 {
			return nil, fmt.Errorf("dmarc: invalid parameter 'ri': negative or zero duration")
		}
		rec.ReportInterval = time.Duration(i) * time.Second
	}

	if rua, ok := params["rua"]; ok {
		rec.ReportURIAggregate = parseURIList(rua)
	}

	if ruf, ok := params["ruf"]; ok {
		rec.ReportURIFailure = parseURIList(ruf)
	}

	if sp, ok := params["sp"]; ok {
		// According to RFC https://datatracker.ietf.org/doc/html/rfc7489#section-6.3
		// If absent, the policy specified by the "p" tag MUST be applied for subdomains.
		// Some People are Keeping this as Empty, which is same as absent.  So, we are setting it as same as "p"
		// Some People are keeping some other value other than none, reject, quarantine into this field , which we are considering as syntax error for now and setting it as same as "p" , opendmarc also does the same.
		rec.SubdomainPolicy, err = parsePolicy(sp, "sp")
		if err != nil {
			rec.SubdomainPolicy = rec.Policy
		}
	}

	return rec, nil
}

func parseParams(s string) (map[string]string, error) {
	pairs := strings.Split(s, ";")
	params := make(map[string]string)
	for _, s := range pairs {
		kv := strings.SplitN(s, "=", 2)
		if len(kv) != 2 {
			// According to RFC, https://datatracker.ietf.org/doc/html/rfc7489#section-6.3
			// A DMARC policy record MUST comply with the formal specification found
			// in Section 6.4 in that the "v" and "p" tags MUST be present and MUST
			// appear in that order.  Unknown tags MUST be ignored.  Syntax errors
			// in the remainder of the record SHOULD be discarded in favor of
			// default values (if any) or ignored outright.
			continue
		}

		// Converts the Values in the Slice to Lower Case , since People Just keeping using random cases.
		kv = toLowerCaseSlice(kv)

		// Adds Support for giving permerror as verdict, when it finds duplicate parameters with different values which are RFC Supported Tags
		if _, ok := params[strings.TrimSpace(kv[0])]; ok {
			if _, ok := RFCSupportedTags[strings.TrimSpace(kv[0])]; ok {
				if params[strings.TrimSpace(kv[0])] != strings.TrimSpace(kv[1]) {
					return params, fmt.Errorf("dmarc: duplicate parameter '%v'", kv[0])
				}
			}
		}

		params[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
	}
	return params, nil
}

func parsePolicy(s, param string) (Policy, error) {
	switch s {
	case "none", "quarantine", "reject":
		return Policy(s), nil
	default:
		return "", fmt.Errorf("dmarc: invalid policy for parameter '%v'", param)
	}
}

func parseAlignmentMode(s, param string) (AlignmentMode, error) {
	switch s {
	case "r", "s":
		return AlignmentMode(s), nil
	default:
		return "", fmt.Errorf("dmarc: invalid alignment mode for parameter '%v'", param)
	}
}

func parseFailureOptions(s string) (FailureOptions, error) {
	l := strings.Split(s, ":")
	var opts FailureOptions
	for _, o := range l {
		switch strings.TrimSpace(o) {
		case "0":
			opts |= FailureAll
		case "1":
			opts |= FailureAny
		case "d":
			opts |= FailureDKIM
		case "s":
			opts |= FailureSPF
		default:
			return 0, errors.New("dmarc: invalid failure option in parameter 'fo'")
		}
	}
	return opts, nil
}

func parseURIList(s string) []string {
	l := strings.Split(s, ",")
	for i, u := range l {
		l[i] = strings.TrimSpace(u)
	}
	return l
}

func toLowerCaseSlice(arr []string) []string {
    lowerCaseArr := make([]string, len(arr))
    for i, v := range arr {
        lowerCaseArr[i] = strings.ToLower(v)
    }
    return lowerCaseArr
}
