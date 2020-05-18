# Kubernetes inspired RBAC for Go

## Walkthrough
This walkthrough is based on [./examples/example.go](./examples/example.go). It shows a simple setup for authorizing web requests.

As a first step, import this package and initialize the authorizer:

```go
import "github.com/djboris9/rbac"

func main() {
    authz := rbac.New()
}
```

Start by adding RBAC roles and rolebindings to the authorizer. We will create
two roles, `read-states` and `node-watcher` first. These will allow you to
access the defined resources with the defined verbs:

```go
func AddRoles(authz *rbac.Authorizer) {
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
}
```

Next, we need to define a rolebinding. It just maps subjects which represents
users, groups and serviceaccounts to the roles. Additionally they can define
to which namespace (scopes) the roles apply, which allows you to use this package
in a multi-tenant system where roles are global and the rolebindings are namespaced/scoped.

```go
func SetRoleBindings(authz *rbac.Authorizer) {
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
}
```

Now you can use the authorizer by passing a subject (the authenticated requestor)
and request informations to the rbac evaluation function:

```go
func ExampleEvaluate(authz *rbac.Authorizer) {
    subject := []rbac.Subject{{
        Name: "system:serviceaccount:alpha:my-watcher",
        Kind: rbac.ServiceAccount,
    }, {
        Name: "system:authenticated",
        Kind: rbac.Group,
    }}

    resource := rbac.Resource{
        Namespace:    "alpha",
        Resource:     "states",
        ResourceName: "nodes",
    }

    // Authorize the request
    result := authz.Eval("patch", subject, resource)

    fmt.Println(result)
    // authorization succeeded for ServiceAccount "system:serviceaccount:alpha:my-watcher" as node-watcher using alpha-node-watchers

    fmt.Println(result.Success)
    // true
}
```

As you see, the request was successfully authorized, we can try to access a different namespace with the same subject_

```go
func ExampleEvaluateNegative(authz *rbac.Authorizer) {
    // ...
    
    // Now try to access something different with the same subject
    resource = rbac.Resource{
        Namespace:    "beta",
        Resource:     "states",
        ResourceName: "nodes",
    }
    result := h.authz.Eval("patch", subject, resource)

    fmt.Println(result)
    // authorization failed for [ServiceAccount:system:serviceaccount:alpha:my-watcher Group:system:authenticated] requesting patch "beta":"states":"nodes"

    fmt.Println(result.Success)
    // false
}
```
This evaluation failed as expected, because we don't have a matching rolebinding and role for this subject and request.

## Rule loaders
In some future, there will be rule loaders that can load the `Roles` and `RoleBindings` from `yaml` files.
