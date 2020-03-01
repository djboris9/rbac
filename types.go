package rbac

import "fmt"

// SubjectKind represents the kind of a subject
type SubjectKind int

const (
	_ SubjectKind = iota // Initial value is invalid to prevent using not initialized fields

	// User represents the SubjectKind for normal users
	User

	// Group represents the SubjectKind for a group that Users or ServiceAccounts can contain
	Group

	// ServiceAccount represents the SubjectKind for artificial users such as applications
	ServiceAccount
)

func (t SubjectKind) String() string {
	return []string{"User", "Group", "ServiceAccount"}[t-1]
}

// Rule represents a rule for authorization.
// TODO: Example and explaination what is required and how combinations are evaluated
type Rule struct {
	Verbs         []string
	Resources     []string
	ResourceNames []string
}

// Role represents a role for authorization.
// A role is successfully evaluated if at least one (OR-logic) of the rules succeeds the evaluation
// TODO: Example
type Role struct {
	Name  string
	Rules []Rule
}

// RoleBinding maps any defined subject to a named role.
// If the namespace is set to an empty string, the evaluation succeedes for every request namespace,
// thus representing a global scope. If it is set to a non empty value, the roles are only evaluated
// for requests containing the same namespace.
type RoleBinding struct {
	Name      string
	Role      string
	Namespace string
	Subjects  []Subject
}

// Subject represents a requestor that requests a resource
type Subject struct {
	Name string
	Kind SubjectKind
}

func (s Subject) String() string {
	return fmt.Sprintf("%s:%s", s.Kind, s.Name)
}

// Resource represents a requested resource. An empty namespace value represents
// the global scope.
type Resource struct {
	Namespace    string
	Resource     string
	ResourceName string
}
