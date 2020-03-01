package rbac

import (
	"bufio"
	"fmt"
	"os"
	"testing"
)

type Evaldata struct {
	Verb     Verb
	Subject  []Subject
	Resource Resource
	Valid    bool
}

func (e Evaldata) String() string {
	return fmt.Sprintf("v:%s,s:%v,n:%s,r:%s,rn:%s", e.Verb, e.Subject,
		e.Resource.Namespace, e.Resource.Resource, e.Resource.ResourceName)
}

func TestVContains(t *testing.T) {
	var failed bool
	failed = failed || vContains([]Verb{}, GET)
	failed = failed || vContains([]Verb{CREATE}, GET)
	failed = failed || !vContains([]Verb{GET}, GET)
	failed = failed || !vContains([]Verb{DELETE, PATCH}, PATCH)
	failed = failed || !vContains([]Verb{PATCH, CREATE}, PATCH)

	if failed {
		t.Fail()
	}
}

func TestSMatchOrEmpty(t *testing.T) {
	var failed bool
	failed = failed || !sMatchOrEmpty("", "abcd")
	failed = failed || sMatchOrEmpty("abcd", "")
	failed = failed || !sMatchOrEmpty("abcd", "abcd")
	failed = failed || sMatchOrEmpty("abcd", "abc")

	if failed {
		t.Fail()
	}
}

func TestSContains(t *testing.T) {
	var failed bool

	failed = failed || !sContains([]string{}, "", true)
	failed = failed || sContains([]string{}, "", false)
	failed = failed || sContains([]string{"x"}, "", true)
	failed = failed || sContains([]string{"x"}, "", false)
	failed = failed || !sContains([]string{"x"}, "x", true)
	failed = failed || !sContains([]string{"x"}, "x", false)
	failed = failed || sContains([]string{"x"}, "y", true)
	failed = failed || sContains([]string{"x"}, "y", false)
	failed = failed || sContains([]string{"a", "x"}, "y", true)
	failed = failed || sContains([]string{"a", "x"}, "y", false)
	failed = failed || sContains([]string{"x", "a"}, "y", true)
	failed = failed || sContains([]string{"x", "a"}, "y", false)

	if failed {
		t.Fail()
	}
}

func createTestdataBasic() ([]Role, []RoleBinding, []Evaldata) {
	// Verb, Ressource, RessourceName
	rules := []Rule{
		{[]Verb{GET}, []string{"res-A"}, []string{"res-1"}},
		{[]Verb{DELETE}, []string{"res-A"}, []string{}},
		{[]Verb{WATCH, LIST}, []string{"res-A", "res-B"}, []string{}},
		{[]Verb{PATCH}, []string{"res-A", "res-B"}, []string{"res-2"}},
		{[]Verb{UPDATE}, []string{"res-A", "res-B"}, []string{"res-1", "res-2"}},
	}

	roles := []Role{
		{Name: "role-A", Rules: []Rule{rules[0]}},
		{Name: "role-B", Rules: []Rule{rules[1]}},
		{Name: "role-C", Rules: []Rule{rules[2], rules[0]}},
		{Name: "role-D", Rules: []Rule{rules[3], rules[1]}},
		{Name: "role-E", Rules: []Rule{rules[4]}},
	}

	subjects := []Subject{
		{Name: "s-user", Type: User},
		{Name: "s-group", Type: Group},
		{Name: "s-serviceaccount", Type: ServiceAccount},
	}

	rolebindings := []RoleBinding{
		{Name: "rb-A", Role: "role-A", Subjects: []Subject{subjects[0]}},
		{Name: "rb-B", Role: "role-B", Subjects: []Subject{subjects[1]}},
		{Name: "rb-C", Role: "role-C", Subjects: []Subject{subjects[2], subjects[0]}},
		{Name: "rb-D", Role: "role-D", Subjects: []Subject{subjects[2], subjects[1]}},
		{Name: "rb-E", Role: "role-E", Subjects: []Subject{subjects[0]}},
		{Name: "rb-F", Role: "role-B", Subjects: []Subject{subjects[0]}, Namespace: "scope-1"},
	}

	ev := []Evaldata{
		{GET, []Subject{{}}, Resource{}, false},
		{GET, []Subject{{"s-user", User}}, Resource{"", "res-A", "res-1"}, true},
		{GET, []Subject{{"s-foo", User}}, Resource{"", "res-A", "res-1"}, false},
		{PATCH, []Subject{{"s-user", User}}, Resource{"", "res-A", "res-1"}, false},
		{GET, []Subject{{"s-user", ServiceAccount}}, Resource{"", "res-A", "res-1"}, false},
		{DELETE, []Subject{{"s-user", User}}, Resource{"scope-1", "res-A", ""}, true},
		{DELETE, []Subject{{"s-user", User}}, Resource{"", "res-A", ""}, false},
	}

	return roles, rolebindings, ev
}

func TestRBACBasic(t *testing.T) {
	// Setup authz
	roles, rolebindings, evaldata := createTestdataBasic()

	a := New()
	for _, role := range roles {
		a.SetRole(role)
	}

	for _, rb := range rolebindings {
		a.SetRoleBinding(rb)
	}

	// Evaluate
	for _, ev := range evaldata {
		res := a.Eval(ev.Verb, ev.Subject, ev.Resource)
		t.Logf("Result: %s", res)
		if res.Success != ev.Valid {
			t.Errorf("Should not validate, but did: %q for evaldata %v", res.String(), ev)
			t.Fail()
		}
	}
}

// generatePermutations generates all permutations according to a model.
// Arg gen must be a slice initialized to 0 with length of model.
// Arg pos must be set to zero.
func generatePermutations(model []int, gen []int, pos int, ret chan<- []int) {
	for i := 0; i < model[pos]; i++ {
		gen[pos] = i

		if pos < len(model)-1 {
			generatePermutations(model, gen, pos+1, ret)
		} else {
			cpy := make([]int, len(gen))
			copy(cpy, gen)
			ret <- cpy
		}
	}

	if pos == 0 {
		close(ret)
	}
}

// modeled after example.yaml
func generateEvaldataExtensive(data chan<- Evaldata) {
	// Input data
	strs := []string{"",
		"node-watcher", "linux", "nodes", "locations", "nodes/states",
		"linux-node-watchers", "bofh", "integrator", "system:core",
		"global-node-watchers", "superusers", "readonly-services",
		"readonly", "auditor"}

	verbs := []Verb{0, GET, LIST, WATCH, DELETE, PATCH, UPDATE}
	stypes := []SubjectType{User, Group, ServiceAccount}

	// Model: verb, SubjectType, Subject, Namespace, Ressource, RessourceName
	model := []int{len(verbs), len(stypes), len(strs), len(strs), len(strs), len(strs)}

	// expCount contains the expected number of permutations
	expCount := 1
	for _, m := range model {
		expCount *= m
	}

	// Generator
	genchan := make(chan []int)
	go generatePermutations(model, make([]int, len(model)), 0, genchan)

	counter := 0
	for gen := range genchan {
		counter += 1

		// Send data through the result channel
		data <- Evaldata{
			Verb: verbs[gen[0]],
			Subject: []Subject{{ // We handle only one subject
				Type: stypes[gen[1]],
				Name: strs[gen[2]],
			}},
			Resource: Resource{
				Namespace:    strs[gen[3]],
				Resource:     strs[gen[4]],
				ResourceName: strs[gen[5]],
			},
		}
	}

	// Validate the number of permutations
	if counter != expCount {
		panic("Generator created invalid number of permutations")
	}

	close(data)
}

// modeled after example.yaml
func createExtensiveAuthorizer() *Authorizer {
	nodeWatcher := Role{
		Name: "node-watcher",
		Rules: []Rule{
			{
				Verbs:     []Verb{GET, LIST, WATCH},
				Resources: []string{"nodes", "locations"},
			},
			{
				Verbs:         []Verb{GET, UPDATE, DELETE},
				Resources:     []string{"nodes/states"},
				ResourceNames: []string{"linux"},
			},
		},
	}
	readonly := Role{
		Name: "readonly",
		Rules: []Rule{
			{
				Verbs:     []Verb{GET, LIST, WATCH},
				Resources: []string{"nodes", "locations"},
			},
		},
	}

	linuxNodeWatchers := RoleBinding{
		Name:      "linux-node-watchers",
		Namespace: "linux",
		Role:      "node-watcher",
		Subjects: []Subject{
			{
				Type: User,
				Name: "bofh",
			},
			{
				Type: ServiceAccount,
				Name: "integrator",
			},
			{
				Type: Group,
				Name: "system:core",
			},
		},
	}

	globalNodeWatchers := RoleBinding{
		Name: "global-node-watchers",
		Role: "node-watcher",
		Subjects: []Subject{
			{
				Type: Group,
				Name: "superusers",
			},
		},
	}

	readOnlyServices := RoleBinding{
		Name: "readonly-services",
		Role: "readonly",
		Subjects: []Subject{
			{
				Type: ServiceAccount,
				Name: "auditor",
			},
		},
	}

	a := New()
	a.SetRole(nodeWatcher)
	a.SetRole(readonly)
	a.SetRoleBinding(linuxNodeWatchers)
	a.SetRoleBinding(globalNodeWatchers)
	a.SetRoleBinding(readOnlyServices)
	return a
}

func TestRBACExtensive(t *testing.T) {
	// Setup authz
	a := createExtensiveAuthorizer()

	// Open data to validate
	fd, err := os.Open("rbac_test_validation.list")
	if err != nil {
		t.Errorf("Got error opening rbac_test_validation.list: %q", err)
		return
	}
	defer fd.Close()
	scanner := bufio.NewScanner(fd)

	// Generate data
	ev := make(chan Evaldata)
	go generateEvaldataExtensive(ev)

	// Go through every permutation and check against validation list
	for e := range ev {
		res := a.Eval(e.Verb, e.Subject, e.Resource)
		if res.Success {
			now := fmt.Sprintf("%s -> %s", e, res)
			fmt.Println(now)

			if scanner.Scan() {
				valid := scanner.Text()
				//t.Errorf("%s", valid)
				if now != valid {
					t.Errorf("Should not validate %s", now)
				}
			} else {
				if err := scanner.Err(); err != nil {
					t.Errorf("Scanner had error %q", err)
					return
				}
				t.Errorf("Successfull validation for %s but expected nothing", e)
			}
		}
	}

	for scanner.Scan() {
		t.Errorf("Expected more valid results: %s", scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		t.Errorf("Scanner had error %q", err)
	}
}
