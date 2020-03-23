package main

import (
	"context"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/djboris9/rbac"
)

func main() {
	// Setup authorizer
	authz := rbac.New()

	authz.SetRole(rbac.Role{
		Name: "read-states",
		Rules: []rbac.Rule{{
			Verbs:     []string{"get", "list", "watch"},
			Resources: []string{"states"},
		}},
	})

	authz.SetRole(rbac.Role{
		Name: "node-watcher",
		Rules: []rbac.Rule{{
			Verbs:     []string{"get", "list"},
			Resources: []string{"nodes"},
		}, {
			Verbs:         []string{"patch"},
			Resources:     []string{"states"},
			ResourceNames: []string{"nodes"},
		}},
	})

	authz.SetRoleBinding(rbac.RoleBinding{
		Name: "states-reading-for-all",
		Role: "read-states",
		Subjects: []rbac.Subject{{
			Name: "system:authenticated",
			Kind: rbac.Group,
		}},
	})

	authz.SetRoleBinding(rbac.RoleBinding{
		Name:      "alpha-node-watchers",
		Namespace: "alpha",
		Role:      "node-watcher",
		Subjects: []rbac.Subject{{
			Name: "bofh",
			Kind: rbac.User,
		}, {
			Name: "administrators",
			Kind: rbac.Group,
		}, {
			Name: "system:serviceaccount:alpha:my-watcher",
			Kind: rbac.ServiceAccount,
		}},
	})

	// Setup HTTP Handler, using our authorizer
	srv := Handlers{authz: authz}
	mux := http.NewServeMux()
	mux.Handle("/states/", srv.Auth(http.HandlerFunc(srv.GetStates)))

	// Just get all nodes
	r := httptest.NewRequest("get", "/states/-/", nil)
	r.Header.Add("X-User", "stephen")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	PrintResult(w)

	// Request node states states as bofh for namespace alpha
	r = httptest.NewRequest("get", "/states/beta/nodes", nil)
	r.Header.Add("X-User", "bofh")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	PrintResult(w)

	// Try to request node states states for namespace alpha, unauthenticated
	r = httptest.NewRequest("get", "/states/beta/nodes", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	PrintResult(w)

	// Patch the nodes state in namespace alpha
	r = httptest.NewRequest("patch", "/states/alpha/nodes", nil)
	r.Header.Add("X-User", "my-watcher")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	PrintResult(w)

	// Try to patch the nodes state in namespace beta
	r = httptest.NewRequest("patch", "/states/beta/nodes", nil)
	r.Header.Add("X-User", "my-watcher")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	PrintResult(w)
}

// Handlers implement http handlers that can use the rbac authorizer
type Handlers struct {
	authz *rbac.Authorizer
}

// Authenticate is a fake authenticator that just maps a http header value
// to a RBAC subject
func Authenticate(h http.Header) []rbac.Subject {
	switch h.Get("X-User") {
	case "boss":
		return []rbac.Subject{{
			Name: "boss",
			Kind: rbac.User,
		}, {
			Name: "bosses",
			Kind: rbac.Group,
		}, {
			Name: "system:authenticated",
			Kind: rbac.Group,
		}}
	case "stephen":
		return []rbac.Subject{{
			Name: "stephen",
			Kind: rbac.User,
		}, {
			Name: "administrators",
			Kind: rbac.Group,
		}, {
			Name: "system:authenticated",
			Kind: rbac.Group,
		}}
	case "bofh":
		return []rbac.Subject{{
			Name: "bofh",
			Kind: rbac.User,
		}, {
			Name: "administrators",
			Kind: rbac.Group,
		}, {
			Name: "system:authenticated",
			Kind: rbac.Group,
		}}
	case "my-watcher":
		return []rbac.Subject{{
			Name: "system:serviceaccount:alpha:my-watcher",
			Kind: rbac.ServiceAccount,
		}, {
			Name: "system:authenticated",
			Kind: rbac.Group,
		}}

	default:
		return []rbac.Subject{{
			Name: "system:unauthenticated",
			Kind: rbac.Group,
		}}
	}
}

// Auth implements an RBAC authorizer by processing the request URLs.
// The URI format is /{resource}/{namespace}/{resourceName}...
func (h Handlers) Auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract subject
		subject := Authenticate(r.Header)

		// Extract request attributes
		components := strings.SplitN(r.URL.Path, "/", 4)
		if len(components) != 4 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		namespace := components[2]
		if namespace == "-" {
			namespace = ""
		}

		rbacResource := rbac.Resource{
			Namespace:    namespace,
			Resource:     components[1],
			ResourceName: components[3],
		}

		// Evaluate authorization
		result := h.authz.Eval(strings.ToLower(r.Method), subject, rbacResource)
		if !result.Success {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(result.String()))
			return
		}

		ctx := context.WithValue(r.Context(), "auth", result)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetStates is a dummy http handler to print authorized requests
func (h Handlers) GetStates(w http.ResponseWriter, r *http.Request) {
	authResult := r.Context().Value("auth").(rbac.Result)
	w.Write([]byte(authResult.String()))
}

// PrintResult dumps informations about a recorded http request
func PrintResult(w *httptest.ResponseRecorder) {
	resp := w.Result()
	body, _ := ioutil.ReadAll(resp.Body)
	log.Printf("%s: %s", resp.Status, body)
}
