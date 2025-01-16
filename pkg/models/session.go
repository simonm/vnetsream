package models

type Session struct {
	ID       string
	Protocol string
	Metadata map[string]interface{}
	// TODO: Add more fields as needed
}

func NewSession(id string, protocol string) *Session {
	return &Session{
		ID:       id,
		Protocol: protocol,
		Metadata: make(map[string]interface{}),
	}
}
