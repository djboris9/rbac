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
	if t < User || t > ServiceAccount {
		return ""
	}

	return []string{"User", "Group", "ServiceAccount"}[t-1]
}

// Rule represents a rule for authorization.
// Verbs and resources are required. In order to evaluate successfully, the
// request parameters must match a combination for all given fields.
type Rule struct {
	Verbs         []string
	Resources     []string
	ResourceNames []string
}

// Role represents a role for authorization.
// A role is successfully evaluated if at least one (OR-logic) of the rules succeeds the evaluation.
//     Name: node-watcher
//     Rules:
//     - Verbs: ["get", "list", "watch"]
//       Resources: ["nodes", "locations"]
//     - Verbs: ["get", "update", "delete"]
//       Resources: ["nodes/states"]
//       ResourceNames: ["linux"]
type Role struct {
	Name  string
	Rules []Rule
}

// RoleBinding maps any defined subject to a named role.
// If the namespace is set to an empty string, the evaluation succeedes for every request namespace,
// thus representing a global scope. If it is set to a non empty value, the roles are only evaluated
// for requests containing the same namespace.
//     Name: administrators-are-node-watchers
//     Role: node-watcher
//     Namespace: nodes-of-bofh
//     Subjects:
//     - Name: bofh
//       Kind: User
//     - Name: administrators
//       Kind: Group
//     - Name: system:serviceaccount:nodes-of-bofh:bugging-software
//       Kind: ServiceAccount
// The example above shows a RoleBinding that applies the operations validated
// by the role `node-watcher` at namespace `nodes-of-bofh` for bfh, administrators
// and a software.
type RoleBinding struct {
	Name      string
	Role      string
	Namespace string
	Subjects  []Subject
}

// Subject represents a requestor that requests a resource. The following block
// shows an example of subjects inspired by Kubernetes RBAC authorization:
//     - Name: bofh
//       Kind: User
//     - Name: administrators
//       Kind: Group
//     - Name: system:serviceaccount:my-namespace:my-account
//       Kind: ServiceAccount
//     - Name: system:authenticated
//       Kind: Group
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

func (r Resource) String() string {
	return fmt.Sprintf("%q:%q:%q", r.Namespace, r.Resource, r.ResourceName)
}

// Result represents a RBAC evaluation result. If the evaluation was successful,
// the field `Success` will be true and the other fields will be set to the parameters
// that were accepted
type Result struct {
	Success     bool
	RoleBinding string
	Role        string
	Subject     string
	SubjectType SubjectKind

	// Request parameters
	RequestingSubject []Subject
	RequestedVerb     string
	RequestedResource Resource
}
