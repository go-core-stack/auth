// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package model

import (
	"net/http"

	"github.com/go-core-stack/auth/route"
)

// Route represents an HTTP route with a URL and HTTP method.
// The Method field uses the custom MethodType defined in the route package.
type Route struct {
	Url    string           // The URL path for the route (e.g., "/api/v1/resource")
	Method route.MethodType // The HTTP method for the route (e.g., route.GET, route.POST)
}

// NewRoute creates a new Route instance from a URL and HTTP method string.
//
// Parameters:
//   - url:    The URL path for the route.
//   - method: The HTTP method as a string (e.g., "GET", "POST").
//
// Returns:
//   - *Route: Pointer to the created Route struct.
//
// The method string is mapped to the corresponding route.MethodType.
// If the method is unknown, it defaults to route.GET.
//
// # Usage
//
//	import (
//	    "github.com/go-core-stack/auth/model"
//	)
//
//	func main() {
//	    r := model.NewRoute("/api/v1/resource", "POST")
//	    fmt.Println(r.Url)    // Output: /api/v1/resource
//	    fmt.Println(r.Method) // Output: 1 (assuming route.POST == 1)
//	}
func NewRoute(url, method string) *Route {
	var m route.MethodType
	switch method {
	case http.MethodHead:
		m = route.HEAD
	case http.MethodPost:
		m = route.POST
	case http.MethodPut:
		m = route.PUT
	case http.MethodPatch:
		m = route.PATCH
	case http.MethodDelete:
		m = route.DELETE
	case http.MethodConnect:
		m = route.CONNECT
	case http.MethodOptions:
		m = route.OPTIONS
	case http.MethodTrace:
		m = route.TRACE
	default:
		m = route.GET // Default to GET if method is unknown
	}
	return &Route{
		Url:    url,
		Method: m,
	}
}
