// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package ws

import (
	"github.com/go-core-stack/auth/model"
	"github.com/go-core-stack/auth/route"
)

// NewRoute returns a model.Route configured for a WebSocket endpoint.
//
// A WebSocket connection is established via an HTTP GET request carrying the
// Upgrade header, so the method is always route.GET.
//
// Parameters:
//   - path:     URL path for the endpoint. May contain variable segments in
//     the "{name}" form, e.g. "/api/v1/ws/events/{eventId}".
//   - resource: RBAC resource name the endpoint operates on.
//   - verb:     RBAC action/verb corresponding to the endpoint.
//   - scopes:   RBAC scopes, top level scope first; nil or empty for an
//     unscoped (tenant level) endpoint.
func NewRoute(path, resource, verb string, scopes []string) *model.Route {
	return &model.Route{
		Url:      path,
		Method:   route.GET,
		Resource: resource,
		Verb:     verb,
		Scopes:   scopes,
	}
}
