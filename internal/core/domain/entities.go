package domain

type FormValues struct {
	To           string
	Port         string
	Interface    string
	InterfaceOut string
	Protocol     string
	Action       string
	From         string
	Comment      string
}

type CellValues struct {
	Index   string
	To      string
	Port    string
	Proto   string
	Action  string
	From    string
	Comment string
}

// Rule is one ufw rule as stored in user.rules / user6.rules
// ("### tuple ###" lines), numbered like `ufw status numbered`.
type Rule struct {
	Number    int    // position shown by `ufw status numbered`
	Action    string // allow, deny, reject, limit
	LogType   string // "", "log" or "log-all"
	Forward   bool   // route rule
	Direction string // in, out
	Protocol  string // any, tcp, udp, ...
	DPort     string // "any", "22", "80,443", "1000:2000"
	Dst       string // "0.0.0.0/0", "::/0", "10.0.0.1", ...
	SPort     string
	Src       string
	DApp      string // destination app profile, "" if none
	SApp      string // source app profile, "" if none
	IfaceIn   string
	IfaceOut  string
	Comment   string // decoded
	V6        bool   // read from user6.rules
}
