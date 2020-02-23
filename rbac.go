package rbac

import (
	"errors"
	"fmt"
	"sync"
)

type Authorizer struct {
	sync.RWMutex
	roles        map[string]Role
	rolebindings map[string]RoleBinding
}

func New() *Authorizer {
	return &Authorizer{
		roles:        map[string]Role{},
		rolebindings: map[string]RoleBinding{},
	}
}

func (a *Authorizer) SetRole(r Role) error {
	if r.Name == "" {
		return errors.New("Role needs to have a name")
	}

	a.Lock()
	a.roles[r.Name] = r
	a.Unlock()
	return nil
}

func (a *Authorizer) SetRoleBinding(r RoleBinding) error {
	if r.Name == "" {
		return errors.New("RoleBinding needs to have a name")
	}

	if r.Role == "" {
		return errors.New("RoleBinding needs to have a Role")
	}

	if len(r.Subjects) == 0 {
		return errors.New("RoleBinding needs to have at least a Subject")
	}

	for _, subject := range r.Subjects {
		if subject.Name == "" {
			return errors.New("every Subject needs to have a name")
		}

		if subject.Type.String() == "" {
			return errors.New("every Subject needs to have a valid type")
		}
	}

	a.Lock()
	a.rolebindings[r.Name] = r
	a.Unlock()
	return nil
}

func (a *Authorizer) DeleteRole(name string) {
	a.Lock()
	delete(a.roles, name)
	a.Unlock()
}

func (a *Authorizer) DeleteRoleBinding(name string) {
	a.Lock()
	delete(a.rolebindings, name)
	a.Unlock()
}

func (a *Authorizer) GetRole(name string) Role {
	a.RLock()
	r := a.roles[name]
	a.RUnlock()
	return r
}

func (a *Authorizer) GetRoleBinding(name string) RoleBinding {
	a.RLock()
	r := a.rolebindings[name]
	a.RUnlock()
	return r
}

type Result struct {
	Success     bool
	RoleBinding string
	Role        string
	Subject     string
	SubjectType SubjectType
}

func (r Result) String() string {
	if !r.Success {
		return "authorization failed"
	}

	return fmt.Sprintf("authorization succeeded for %s %q as %s using %s", r.SubjectType, r.Subject, r.Role, r.RoleBinding)
}

func (a *Authorizer) Eval(verb Verb, subject []Subject, ressource Resource) Result {
	a.RLock()

	var res Result
	var r bool
	for rb := range a.rolebindings {
		// Check if scope matches rolebinding
		scopeOk := sMatchOrEmpty(a.rolebindings[rb].Scope, ressource.Scope)

		// Check if subject matches rolebinding
		var subjectOk bool
		var subjectApplied *Subject
		for _, reqSubject := range subject {
			for _, subj := range a.rolebindings[rb].Subjects {
				subjectValidated := (subj.Name == reqSubject.Name && subj.Type == reqSubject.Type)
				subjectOk = subjectOk || subjectValidated
				if subjectValidated {
					subjectApplied = &subj
				}
			}
		}

		// Check if a rule matches the ressource
		if role, ok := a.roles[a.rolebindings[rb].Role]; ok {
			var roleOk bool
			for _, rule := range role.Rules {
				ruleRessourcesOk := sContains(rule.Resources, ressource.Resource, false)
				ruleResourceNamesOk := sContains(rule.ResourceNames, ressource.ResourceName, true)
				ruleVerbsOk := vContains(rule.Verbs, verb)
				roleOk = roleOk || (ruleRessourcesOk && ruleResourceNamesOk && ruleVerbsOk)
			}

			// Check if everything succeeded so we can stop here
			r = (scopeOk && subjectOk && roleOk)
			if r {
				res = Result{
					Success:     r,
					RoleBinding: a.rolebindings[rb].Name,
					Role:        role.Name,
					Subject:     subjectApplied.Name,
					SubjectType: subjectApplied.Type,
				}
				break
			}
		}
	}
	a.RUnlock()

	res.Success = r
	return res
}

func sMatchOrEmpty(s, s2 string) bool {
	return s == "" || s == s2
}

// emptyOk: An empty slice will return true
func sContains(sl []string, s string, emptyOk bool) bool {
	var ret bool
	ret = ret || (len(sl) == 0 && emptyOk)
	for _, s2 := range sl {
		ret = ret || (s == s2)
	}
	return ret
}

func vContains(vl []Verb, v Verb) bool {
	var ret bool
	for _, v2 := range vl {
		ret = ret || (v == v2)
	}
	return ret
}
