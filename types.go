package rbac

type Verb int

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

type Resource struct {
	Namespace    string
	Resource     string
	ResourceName string
}
