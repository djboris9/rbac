package rbac

type Verb int

const (
	GET Verb = iota
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

type SubjectType int

const (
	User SubjectType = iota
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
	Name     string
	Role     string // References Role
	Scope    string
	Subjects []Subject
}

type Subject struct {
	Name string
	Type SubjectType
}

type Resource struct {
	Scope        string
	Resource     string
	ResourceName string
}
