package rbac

import "fmt"

type SubjectType int // TODO rename to kind

const (
	User SubjectType = iota // TODO 0 shoud be invalid
	Group
	ServiceAccount
)

func (t SubjectType) String() string {
	return []string{"User", "Group", "ServiceAccount"}[t]
}

type Rule struct {
	Verbs         []string
	Resources     []string
	ResourceNames []string
}

type Role struct {
	Name  string
	Rules []Rule
}

type RoleBinding struct {
	Name      string
	Role      string // References Role
	Namespace string
	Subjects  []Subject
}

type Subject struct {
	Name string
	Type SubjectType // TODO rename to kind
}

func (s Subject) String() string {
	return fmt.Sprintf("%s:%s", s.Type, s.Name)
}

type Resource struct {
	Namespace    string
	Resource     string
	ResourceName string
}
