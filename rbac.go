package rbac

import (
	"errors"
	"fmt"
	"sync"
)

// Authorizer provides a RBAC authorizer. It must be created by calling New()
type Authorizer struct {
	sync.RWMutex
	roles        map[string]Role
	rolebindings map[string]RoleBinding
}

// New instantiates a RBAC authorizer
func New() *Authorizer {
	return &Authorizer{
		roles:        map[string]Role{},
		rolebindings: map[string]RoleBinding{},
	}
}

// SetRole validates a role and adds it to the Authorizer
func (a *Authorizer) SetRole(r Role) error {
	if r.Name == "" {
		return errors.New("Role needs to have a name")
	}

	for _, rule := range r.Rules {
		if len(rule.Verbs) == 0 {
			return errors.New("Every rule needs at least a verb")
		}

		if len(rule.Resources) == 0 {
			return errors.New("Every rule needs at least a resource")
		}

		for _, v := range rule.Verbs {
			if v == "" {
				return errors.New("Every rule needs to have valid verbs")
			}
		}
	}

	a.Lock()
	a.roles[r.Name] = r
	a.Unlock()
	return nil
}

// SetRoleBinding validates a role binding and adds it to the Authorizer
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

		if subject.Kind.String() == "" {
			return errors.New("every Subject needs to have a valid type")
		}
	}

	a.Lock()
	a.rolebindings[r.Name] = r
	a.Unlock()
	return nil
}

// DeleteRole removes a named role from the Authorizer
func (a *Authorizer) DeleteRole(name string) {
	a.Lock()
	delete(a.roles, name)
	a.Unlock()
}

// DeleteRoleBinding removes a named role binding from the Authorizer
func (a *Authorizer) DeleteRoleBinding(name string) {
	a.Lock()
	delete(a.rolebindings, name)
	a.Unlock()
}

// GetRole returns the named role registered in the Authorizer
func (a *Authorizer) GetRole(name string) Role {
	a.RLock()
	r := a.roles[name]
	a.RUnlock()
	return r
}

// GetRoleBinding returns the named role binding registered in the Authorizer
func (a *Authorizer) GetRoleBinding(name string) RoleBinding {
	a.RLock()
	r := a.rolebindings[name]
	a.RUnlock()
	return r
}

// Result represents an RBAC evaluation result. If the evaluation was successful,
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

// String returns a human readable string with the reason why a authorization
// succeeded.
func (r Result) String() string {
	if !r.Success {
		return fmt.Sprintf("authorization failed for %s requesting %s %s",
			r.RequestingSubject, r.RequestedVerb, r.RequestedResource)
	}

	return fmt.Sprintf("authorization succeeded for %s %q as %s using %s", r.SubjectType, r.Subject, r.Role, r.RoleBinding)
}

// Eval evaluates the RBAC rules from the Authorizer according to a request and returns the authorization result.
// The request is represented by a verb, the requesting subject and the requested resource.
func (a *Authorizer) Eval(verb string, subject []Subject, resource Resource) Result {
	a.RLock()

	var res Result
	var r bool
	for rb := range a.rolebindings {
		// Check if scope matches rolebinding
		scopeOk := sMatchOrEmpty(a.rolebindings[rb].Namespace, resource.Namespace)

		// Check if subject matches rolebinding
		var subjectOk bool
		var subjectApplied Subject
		for _, reqSubject := range subject {
			for _, subj := range a.rolebindings[rb].Subjects {
				subjectValidated := (subj.Name == reqSubject.Name && subj.Kind == reqSubject.Kind)
				subjectOk = subjectOk || subjectValidated
				if subjectValidated {
					subjectApplied = subj
				}
			}
		}

		// Check if a rule matches the resource
		if role, ok := a.roles[a.rolebindings[rb].Role]; ok {
			var roleOk bool
			for _, rule := range role.Rules {
				ruleRessourcesOk := sContains(rule.Resources, resource.Resource, false)
				ruleResourceNamesOk := sContains(rule.ResourceNames, resource.ResourceName, true)
				ruleVerbsOk := sContains(rule.Verbs, verb, false)
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
					SubjectType: subjectApplied.Kind,
				}
				break
			}
		}
	}
	a.RUnlock()

	res.RequestedVerb = verb
	res.RequestingSubject = subject // maybe deep copy subject as it is a slice?
	res.RequestedResource = resource

	return res
}

// sMatchOrEmpty returns true if `s` is an empty string or equals to `s2`
func sMatchOrEmpty(s, s2 string) bool {
	return s == "" || s == s2
}

// sContains returns true if `sl` contains `s`.
// If `emptyOk` is true and `sl` is an empty slice, it will return also true.
func sContains(sl []string, s string, emptyOk bool) bool {
	var ret bool
	ret = ret || (len(sl) == 0 && emptyOk)
	for _, s2 := range sl {
		ret = ret || (s == s2)
	}
	return ret
}
