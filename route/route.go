// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package route

import (
	"github.com/go-core-stack/core/db"
	"github.com/go-core-stack/core/errors"
	"github.com/go-core-stack/core/table"
)

type MethodType int32

const (
	GET MethodType = iota
	HEAD
	POST
	PUT
	PATCH
	DELETE
	CONNECT
	OPTIONS
	TRACE
)

type Key struct {
	Url    string     `json:"url,omitempty"`
	Method MethodType `json:"method,omitempty"`
}

type Route struct {
	Key      *Key   `json:"key,omitempty"`
	Endpoint string `json:"endpoint,omitempty"`

	// If the route is publically accessible, then rest of the fields
	// below are not relevant
	IsPublic *bool `json:"isPublic,omitempty"`

	// if route is user specific RBAC constructs are not valid, rest of
	// the fields below are not relevant
	IsUserSpecific *bool `json:"isUserSpecific,omitempty"`

	// RBAC constructs associated with Route
	ResourceName string `json:"resourceName,omitempty"`
	Verb         string `json:"verb,omitempty"`
}

type RouteTable struct {
	table.Table[Key, Route]
	col db.StoreCollection
}

var routeTable *RouteTable

func GetRouteTable() (*RouteTable, error) {
	if routeTable != nil {
		return routeTable, nil
	}

	return nil, errors.Wrapf(errors.NotFound, "route table not found")
}

func LocateRouteTable(client db.StoreClient) (*RouteTable, error) {
	if routeTable != nil {
		return routeTable, nil
	}

	col := client.GetCollection(ServicesDatabaseName, RoutesCollectionName)
	tbl := &RouteTable{
		col: col,
	}

	err := tbl.Initialize(col)
	if err != nil {
		return nil, err
	}
	routeTable = tbl

	return routeTable, nil
}
