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

import "net/http"

type keystoneAuth struct {
}

func (ka *keystoneAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer ka.next.ServeHTTP(w, r)
	ctx := GetProxyContext(r)
	if ctx.Authorize == nil {
		ctx.Authorize = ka.authorize
	}

}

func (ka *keystoneAuth) authorize(r *http.Request) {
	// allow OPTIONS requests to proceed as normal
	if r.Method == "OPTIONS" {
		return true
	}
	identityMap := extractIdentity(r)
}
func extractIdentity(r *http.Request) map[string]string {
	identity := make(map[string]string)
	if r.Header.Get("X-Identity-Status") != "Confirmed" {
		return identity
	}

	identity["userID"] = r.Header.Get("X-User-Id")
	identity["userName"] = r.Header.Get("X-User-Name")
	identity["tenantID"] = r.Header.Get("X-Project-Id")
	identity["tenantName"] = r.Header.Get("X-Project-Name")
	identity["roles"] = r.Header.Get("X-Roles")
	identity["userDomainID"] = r.Header.Get("X-User-Domain-ID")
	identity["userDomainName"] = r.Header.Get("X-User-Domain-Name")
	identity["projectDomainID"] = r.Header.Get("X-Project-Domain-ID")
	identity["projectDomainName"] = r.Header.Get("X-Project-Domain-Name")

	return identity
}

func NewKeystoneAuth(config conf.Section) (func(http.Handler) http.Handler, error) {
	return func(next http.Handler) http.Handler {
		return &authToken{
			next: next,
		}
	}, nil
}
