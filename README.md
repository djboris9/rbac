# Kubernetes inspired RBAC for Go

Status: *In development*

## Walkthrough
This walkthrough is based on [./examples/example.go](./examples/example.go).

As a first step, import this package and initialize the authorizer:

    import "github.com/djboris9/rbac"

    func main() {
	authz := rbac.New()
    }

Start by adding RBAC roles and rolebindings to the authorizer. We will create
two roles, `read-states` and `node-watcher` first. These will allow you to
access the defined resources with the defined verbs:

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

Next, we need to define a rolebinding. It just maps subjects which represents
users, groups and serviceaccounts to the roles. Additionally they can define
to which namespace (scopes) the roles apply, which allows you to use this package
in a multi-tenant system where roles are global and the rolebindings are namespaced/scoped.

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

## Rule loaders
*TODO*
