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
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/troubling/hummingbird/common"
	"github.com/troubling/hummingbird/common/conf"
	"go.uber.org/zap"
)

type keystoneAuth struct {
	resellerPrefixes  []string
	accountRules      map[string]map[string][]string
	resellerAdminRole string
	next              http.Handler
}

func (ka *keystoneAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	identityMap := extractIdentity(r)
	defer ka.next.ServeHTTP(w, r)
	ctx := GetProxyContext(r)
	if len(identityMap) == 0 {
		if ctx.Authorize == nil {
			ctx.Authorize = ka.authorizeAnonymous
		}
	} else {
		if ctx.Authorize == nil {
			ctx.Authorize = ka.authorize
		}
		userRoles := common.SliceFromCSV(identityMap["roles"])
		for _, r := range userRoles {
			if ka.resellerAdminRole == strings.ToLower(r) {
				ctx.ResellerRequest = true
				break
			}
		}
	}
}

func (ka *keystoneAuth) accountMatchesTenant(account string, tenantID string) bool {
	for _, prefix := range ka.resellerPrefixes {
		if fmt.Sprintf("%s%s", prefix, tenantID) == account {
			return true
		}
	}
	return false
}

func (ka *keystoneAuth) setProjectDomainID(r *http.Request, pathParts map[string]string, identityMap map[string]string) {
	for k := range r.Header {
		if k == "X-Account-Sysmeta-Project-Domain-ID" {
			return
		}
	}
	if pathParts["obj"] != "" || (pathParts["container"] != "" && r.Method != "PUT") ||
		common.StringInSlice(r.Method, []string{"PUT", "POST"}) {
		return
	}
	tenantID := identityMap["tenantID"]
	ctx := GetProxyContext(r)
	sysmetaID := ctx.GetAccountInfo(pathParts["account"]).SysMetadata["Project-Domain-ID"]
	reqID, newID := "", ""
	if ka.accountMatchesTenant(pathParts["account"], tenantID) {
		reqID = identityMap["projectDomainID"]
		newID = reqID
	}
	if sysmetaID == "" && reqID == "default" {
		newID = reqID
	}
	if newID != "" {
		r.Header.Set("X-Account-Sysmeta-Project-Domain-ID", newID)
	}
}

func (ka *keystoneAuth) authorizeCrossTenant(userID string, userName string,
	tenantID string, tenantName string, roles []string) string {
	tenantMatch := []string{tenantID, "*"}
	userMatch := []string{userID, "*"}
	for _, tenant := range tenantMatch {
		for _, user := range userMatch {
			s := fmt.Sprintf("%s:%s", tenant, user)
			if common.StringInSlice(s, roles) {
				return s
			}
		}
	}
	return ""
}

func (ka *keystoneAuth) authorize(r *http.Request) bool {
	identityMap := extractIdentity(r)
	ctx := GetProxyContext(r)

	tenantID := identityMap["tenantID"]
	tenantName := identityMap["tenantName"]
	userID := identityMap["userID"]
	userName := identityMap["userName"]

	referrers, roles := ParseACL(ctx.ACL)

	// allow OPTIONS requests to proceed as normal
	if r.Method == "OPTIONS" {
		return true
	}
	pathParts, err := common.ParseProxyPath(r.URL.Path)
	if err != nil {
		ctx.Logger.Error("Unable to parse URL", zap.Error(err))
		return false
	}

	ka.setProjectDomainID(r, pathParts, identityMap)
	userRoles := []string{}
	for _, userRole := range common.SliceFromCSV(identityMap["roles"]) {
		userRoles = append(userRoles, strings.ToLower(userRole))
	}
	if common.StringInSlice(ka.resellerAdminRole, userRoles) {
		ctx.Logger.Debug("User has reseller admin authorization", zap.String("userid", tenantID))
		return true
	}

	if pathParts["container"] == "" && pathParts["object"] == "" &&
		r.Method == "DELETE" {
		ctx.Logger.Debug("User is not allowed to delete its own account",
			zap.String("tenantName", tenantName),
			zap.String("userName", userName))
		return false
	}
	matchedACL := ""
	if len(roles) > 0 {
		matchedACL = ka.authorizeCrossTenant(userID, userName, tenantID, tenantName, roles)
	}
	if matchedACL != "" {
		ctx.Logger.Debug("user allowed in ACL authorizing", zap.String("user", matchedACL))
		return true
	}

	isAuthorized, authErr := ka.authorizeUnconfirmedIdentity(r, pathParts, referrers, roles)

	if isAuthorized {
		return true
	}

	if !ka.accountMatchesTenant(pathParts["account"], tenantID) {
		return false
	}
	accountPrefix, _ := ka.getAccountPrefix(pathParts["account"])
	operatorRoles := ka.accountRules[accountPrefix]["operator_roles"]
	haveOperatorRole := false
	for _, or := range operatorRoles {
		if common.StringInSlice(or, userRoles) {
			haveOperatorRole = true
			break
		}
	}
	serviceRoles := ka.accountRules[accountPrefix]["service_roles"]
	haveServiceRole := false
	for _, or := range serviceRoles {
		if common.StringInSlice(or, userRoles) {
			haveServiceRole = true
			break
		}
	}
	allowed := false
	if haveOperatorRole && (len(serviceRoles) > 0 && haveServiceRole) {
		allowed = true
	} else if haveOperatorRole && !haveServiceRole {
		allowed = true
	}
	if allowed {
		return true
	}
	if !isAuthorized && authErr == nil {
		return false
	}

	for _, role := range roles {
		if common.StringInSlice(role, userRoles) {
			return true
		}

	}
	return false
}

func (ka *keystoneAuth) getAccountPrefix(account string) (string, bool) {
	// Empty prefix matches everything, so try to match others first
	for _, prefix := range ka.resellerPrefixes {
		if prefix != "" && strings.HasPrefix(account, prefix) {
			return prefix, true
		}
	}
	for _, prefix := range ka.resellerPrefixes {
		if prefix == "" {
			return "", true
		}
	}
	return "", false
}

func (ka *keystoneAuth) authorizeAnonymous(r *http.Request) bool {
	ctx := GetProxyContext(r)
	pathParts, err := common.ParseProxyPath(r.URL.Path)
	if err != nil {
		ctx.Logger.Error("Unable to parse URL", zap.Error(err))
		return false
	}
	// allow OPTIONS requests to proceed as normal
	if r.Method == "OPTIONS" {
		return true
	}
	isAuthorized := false
	if pathParts["account"] != "" {
		if prefix, ok := ka.getAccountPrefix(pathParts["account"]); ok {
			if common.StringInSlice(prefix, ka.resellerPrefixes) {
				isAuthorized = true
			}
		}
	}
	if !isAuthorized {
		return false
	}

	referrers, roles := ParseACL(ctx.ACL)
	isAuthorized, _ = ka.authorizeUnconfirmedIdentity(r, pathParts, referrers, roles)

	if !isAuthorized {
		return false
	}
	return true
}

func (ka *keystoneAuth) authorizeUnconfirmedIdentity(r *http.Request, pathParts map[string]string, referrers []string, roles []string) (bool, error) {
	ctx := GetProxyContext(r)
	// Allow container Sync
	if ci := ctx.GetContainerInfo(pathParts["account"], pathParts["container"]); ci != nil {
		if ci.SyncKey == r.Header.Get("X-Container-Sync-Key") && r.Header.Get("X-Timestamp") != "" {
			return true, nil
		}
	}
	if ReferrerAllowed(r.Referer(), referrers) {
		if pathParts["obj"] != "" || common.StringInSlice(".rlistings", roles) {
			return true, nil
		}
		return false, nil
	}
	return false, errors.New("unable to confirm identity")
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
		return &keystoneAuth{
			next:              next,
			resellerPrefixes:  resellerPrefixes,
			accountRules:      accountRules,
			resellerAdminRole: strings.ToLower(config.GetDefault("reseller_admin_role", "ResellerAdmin")),
		}
	}, nil
}
