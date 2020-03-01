package rbac

import "fmt"

type SubjectKind int

const (
	_ SubjectKind = iota // Initial value is invalid to prevent using not initialized fields
	User
	Group
	ServiceAccount
)

func (t SubjectKind) String() string {
	return []string{"User", "Group", "ServiceAccount"}[t-1]
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
	Kind SubjectKind
}

func (s Subject) String() string {
	return fmt.Sprintf("%s:%s", s.Kind, s.Name)
}

type Resource struct {
	Namespace    string
	Resource     string
	ResourceName string
}
