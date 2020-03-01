package rbac

import (
	"bufio"
	"fmt"
	"os"
	"testing"
)

// Evaldata provides input data for a evaluation with the hint if it should validate
// correctly
type Evaldata struct {
	Verb     string
	Subject  []Subject
	Resource Resource
	Valid    bool
}

func (e Evaldata) String() string {
	return fmt.Sprintf("v:%s,s:%v,n:%s,r:%s,rn:%s", e.Verb, e.Subject,
		e.Resource.Namespace, e.Resource.Resource, e.Resource.ResourceName)
}

// TestSMatchOrEmpty tests the SMatchOrEmpty function
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

// TestSContains tests the SContains function
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

// createTestdataBasic creates the inputdata for TestRBACBasic
func createTestdataBasic() ([]Role, []RoleBinding, []Evaldata) {
	// Rule has the form: Verb, Ressource, RessourceName
	rules := []Rule{
		{[]string{"get"}, []string{"res-A"}, []string{"res-1"}},
		{[]string{"delete"}, []string{"res-A"}, []string{}},
		{[]string{"watch", "list"}, []string{"res-A", "res-B"}, []string{}},
		{[]string{"patch"}, []string{"res-A", "res-B"}, []string{"res-2"}},
		{[]string{"update"}, []string{"res-A", "res-B"}, []string{"res-1", "res-2"}},
	}

	roles := []Role{
		{Name: "role-A", Rules: []Rule{rules[0]}},
		{Name: "role-B", Rules: []Rule{rules[1]}},
		{Name: "role-C", Rules: []Rule{rules[2], rules[0]}},
		{Name: "role-D", Rules: []Rule{rules[3], rules[1]}},
		{Name: "role-E", Rules: []Rule{rules[4]}},
	}

	subjects := []Subject{
		{Name: "s-user", Kind: User},
		{Name: "s-group", Kind: Group},
		{Name: "s-serviceaccount", Kind: ServiceAccount},
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
		{"get", []Subject{{}}, Resource{}, false},
		{"get", []Subject{{"s-user", User}}, Resource{"", "res-A", "res-1"}, true},
		{"get", []Subject{{"s-foo", User}}, Resource{"", "res-A", "res-1"}, false},
		{"patch", []Subject{{"s-user", User}}, Resource{"", "res-A", "res-1"}, false},
		{"get", []Subject{{"s-user", ServiceAccount}}, Resource{"", "res-A", "res-1"}, false},
		{"delete", []Subject{{"s-user", User}}, Resource{"scope-1", "res-A", ""}, true},
		{"delete", []Subject{{"s-user", User}}, Resource{"", "res-A", ""}, false},
	}

	return roles, rolebindings, ev
}

// TestRBACBasic tests the evaluation of RBAC rules with a few simple tests
func TestRBACBasic(t *testing.T) {
	// Setup authz
	roles, rolebindings, evaldata := createTestdataBasic()

	a := New()
	for _, role := range roles {
		if err := a.SetRole(role); err != nil {
			t.Fatalf("SetRole failed with %q", err)
		}
	}

	for _, rb := range rolebindings {
		if err := a.SetRoleBinding(rb); err != nil {
			t.Fatalf("SetRoleBinding failed with %q", err)
		}
	}

	// Evaluate
	for _, ev := range evaldata {
		res := a.Eval(ev.Verb, ev.Subject, ev.Resource)
		t.Logf("Result: %s", res)
		if res.Success != ev.Valid {
			t.Fatalf("Should not validate, but did: %q for evaldata %v", res.String(), ev)
		}
	}
}

// generatePermutations generates all permutations according to a model.
// Argument `gen` must be a slice initialized to 0 with length of model.
// Argument `pos` must be set to zero.
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

// generateEvaldataExtensive generates Evaldata objects with all possible permutations
// modeled after the output of function createExtensiveAuthorizer
func generateEvaldataExtensive(data chan<- Evaldata) {
	// All possible input arguments
	strs := []string{"",
		"node-watcher", "linux", "nodes", "locations", "nodes/states",
		"linux-node-watchers", "bofh", "integrator", "system:core",
		"global-node-watchers", "superusers", "readonly-services",
		"readonly", "auditor", "get", "list", "watch", "delete",
		"patch", "update"}
	stypes := []SubjectKind{User, Group, ServiceAccount, 42}

	// Model: verb, SubjectType, Subject, Namespace, Ressource, RessourceName
	model := []int{len(strs), len(stypes), len(strs), len(strs), len(strs), len(strs)}

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
		counter++

		// Send data through the result channel
		data <- Evaldata{
			Verb: strs[gen[0]],
			Subject: []Subject{{ // We handle only one subject
				Kind: stypes[gen[1]],
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

// createExtensiveAuthorizer returns an Authorizer that is configured for
// TestRBACExtensive
func createExtensiveAuthorizer() *Authorizer {
	nodeWatcher := Role{
		Name: "node-watcher",
		Rules: []Rule{
			{
				Verbs:     []string{"get", "list", "watch"},
				Resources: []string{"nodes", "locations"},
			},
			{
				Verbs:         []string{"get", "update", "delete"},
				Resources:     []string{"nodes/states"},
				ResourceNames: []string{"linux"},
			},
		},
	}
	readonly := Role{
		Name: "readonly",
		Rules: []Rule{
			{
				Verbs:     []string{"get", "list", "watch"},
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
				Kind: User,
				Name: "bofh",
			},
			{
				Kind: ServiceAccount,
				Name: "integrator",
			},
			{
				Kind: Group,
				Name: "system:core",
			},
		},
	}

	globalNodeWatchers := RoleBinding{
		Name: "global-node-watchers",
		Role: "node-watcher",
		Subjects: []Subject{
			{
				Kind: Group,
				Name: "superusers",
			},
		},
	}

	readOnlyServices := RoleBinding{
		Name: "readonly-services",
		Role: "readonly",
		Subjects: []Subject{
			{
				Kind: ServiceAccount,
				Name: "auditor",
			},
		},
	}

	a := New()
	err := a.SetRole(nodeWatcher)
	if err != nil {
		panic("SetRole failed")
	}

	err = a.SetRole(readonly)
	if err != nil {
		panic("SetRole failed")
	}

	err = a.SetRoleBinding(linuxNodeWatchers)
	if err != nil {
		panic("SetRoleBinding failed")
	}

	err = a.SetRoleBinding(globalNodeWatchers)
	if err != nil {
		panic("SetRoleBinding failed")
	}

	err = a.SetRoleBinding(readOnlyServices)
	if err != nil {
		panic("SetRoleBinding failed")
	}

	return a
}

// TestRBACExtensive tests all possible permutations provided by generateEvaldataExtensive
// for the Authorizer created by createExtensiveAuthorizer.
// This test ensures that the evaluation of the rules doesn't change over time
// and works as expected. The permutations which evaluate correctly are checked
// against `rbac_test_validation.list` which also contains the reason for a
// successful evaluation.
func TestRBACExtensive(t *testing.T) {
	// Setup authorizer including rules
	a := createExtensiveAuthorizer()

	// Open data to validate
	fd, err := os.Open("rbac_test_validation.list")
	if err != nil {
		t.Fatalf("Got error opening rbac_test_validation.list: %q", err)
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
			// Format our tuple (Evaldata, Reason) as string
			// in order to match it against our validation list
			now := fmt.Sprintf("%s -> %s", e, res)
			t.Logf("Validated: %s", now)

			if scanner.Scan() {
				valid := scanner.Text()
				if now != valid {
					t.Fatalf("Should not validate according to validation.list: %s", now)
				}
			} else {
				if err := scanner.Err(); err != nil {
					t.Fatalf("Scanner had error %q", err)
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
