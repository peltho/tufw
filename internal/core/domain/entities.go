package domain

type FormValues struct {
	To           *string
	Port         *string
	Interface    *string
	InterfaceOut *string
	Protocol     *string
	Action       string
	From         *string
	Comment      *string
}

type CellValues struct {
	Index   string
	To      string
	Port    string
	Action  string
	From    string
	Comment string
}
