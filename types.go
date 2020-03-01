package rbac

import "fmt"

type Verb int

// TODO: Maybe verbs should also be strings to allow individual operations
// like impersonate or use in Kubernetes.
// The set of verbs should be only recommended
// https://kubernetes.io/docs/reference/access-authn-authz/authorization/#determine-the-request-verb
const (
	GET Verb = iota // TODO 0 should be invalid
	LIST
	WATCH
	CREATE
	UPDATE
	PATCH
	DELETE
)

func (v Verb) String() string {
	return []string{"get", "list", "watch", "create", "update", "patch", "delete"}[v]
}

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
	Verbs         []Verb
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
