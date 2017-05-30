//  Copyright (c) 2017 Rackspace
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
//  implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

package middleware

import (
	"net/http"
	"strings"

	"github.com/troubling/hummingbird/common/conf"
	"github.com/troubling/hummingbird/common/srv"
)

type keystoneAuth struct {
	resellerPrefixes  []string
	accountRules      map[string]map[string][]string
	resellerAdminRole string
}

func (ka *keystoneAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	identityMap := extractIdentity(r)
	defer ka.next.ServeHTTP(w, r)
	ctx := GetProxyContext(r)

	if ctx.AuthorizeOveride {
		return
	}
	if len(identityMap) == 0 {
		if ctx.Authorize == nil {
			ctx.Authorize = ka.authorizeAnonymous
		}
	} else {
		if ctx.Authorize == nil {
			ctx.Authorize = ka.authorize
		}
		userRoles = SliceFromCSV(identityMap["roles"])
		for _, r := range userRoles {
			if ka.resellerAdminRole == strings.ToLower(r) {
				ctx.ResellerRequest = True
				break
			}
		}
	}
}

func (ka *keystoneAuth) authorize(r *http.Request) bool {
	// allow OPTIONS requests to proceed as normal
	if r.Method == "OPTIONS" {
		return true
	}
	identityMap := extractIdentity(r)
}

func (ka *keystoneAuth) authorizeAnonymous(r *http.Request) bool {
	// allow OPTIONS requests to proceed as normal
	if r.Method == "OPTIONS" {
		return true
	}
	pathParts, err := common.ParseProxyPath(request.URL.Path)
	if err != nil {
		srv.StandardResponse(writer, 400)
		return
	}
}

func extractIdentity(r *http.Request) map[string]string {
	identity := make(map[string]string)
	if r.Header.Get("X-Identity-Status") != "Confirmed" || r.Header.Get("X-Service-Identity-Status") != "Confirmed" {
		return identity
	}

	identity["userID"] = r.Header.Get("X-User-Id")
	identity["userName"] = r.Header.Get("X-User-Name")
	identity["tenantID"] = r.Header.Get("X-Project-Id")
	identity["tenantName"] = r.Header.Get("X-Project-Name")
	identity["roles"] = r.Header.Get("X-Roles")
	identity["serviceRoles"] = r.Header.Get("X-Service-Roles")
	identity["userDomainID"] = r.Header.Get("X-User-Domain-ID")
	identity["userDomainName"] = r.Header.Get("X-User-Domain-Name")
	identity["projectDomainID"] = r.Header.Get("X-Project-Domain-ID")
	identity["projectDomainName"] = r.Header.Get("X-Project-Domain-Name")

	return identity
}

func NewKeystoneAuth(config conf.Section) (func(http.Handler) http.Handler, error) {
	defaultRules := map[string][]string{"operator_roles": {"admin", "swiftoperator"},
		"service_roles": {}}
	resellerPrefixes, accountRules := conf.ReadResellerOptions(config, defaultRules)
	return func(next http.Handler) http.Handler {
		return &authToken{
			next:              next,
			resellerPrefixes:  resellerPrefixes,
			accountRules:      accountRules,
			resellerAdminRole: strings.ToLower(config.GetDefault("reseller_admin_role", "ResellerAdmin")),
		}
	}, nil
}
