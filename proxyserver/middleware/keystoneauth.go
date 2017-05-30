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

	// # Cleanup - make sure that a previously set swift_owner setting is
 //        # cleared now. This might happen for example with COPY requests.
 //        req.environ.pop('swift_owner', None)

 //        tenant_id, tenant_name = env_identity['tenant']
 //        user_id, user_name = env_identity['user']
 //        referrers, roles = swift_acl.parse_acl(getattr(req, 'acl', None))

 //        # allow OPTIONS requests to proceed as normal
 //        if req.method == 'OPTIONS':
 //            return

 //        try:
 //            part = req.split_path(1, 4, True)
 //            version, account, container, obj = part
 //        except ValueError:
 //            return HTTPNotFound(request=req)

 //        self._set_project_domain_id(req, part, env_identity)

 //        user_roles = [r.lower() for r in env_identity.get('roles', [])]
 //        user_service_roles = [r.lower() for r in env_identity.get(
 //                              'service_roles', [])]

 //        # Give unconditional access to a user with the reseller_admin
 //        # role.
 //        if self.reseller_admin_role in user_roles:
 //            msg = 'User %s has reseller admin authorizing'
 //            self.logger.debug(msg, tenant_id)
 //            req.environ['swift_owner'] = True
 //            return

 //        # If we are not reseller admin and user is trying to delete its own
 //        # account then deny it.
 //        if not container and not obj and req.method == 'DELETE':
 //            # User is not allowed to issue a DELETE on its own account
 //            msg = 'User %s:%s is not allowed to delete its own account'
 //            self.logger.debug(msg, tenant_name, user_name)
 //            return self.denied_response(req)

 //        # cross-tenant authorization
 //        matched_acl = None
 //        if roles:
 //            allow_names = self._is_name_allowed_in_acl(req, part, env_identity)
 //            matched_acl = self._authorize_cross_tenant(user_id, user_name,
 //                                                       tenant_id, tenant_name,
 //                                                       roles, allow_names)
 //        if matched_acl is not None:
 //            log_msg = 'user %s allowed in ACL authorizing.'
 //            self.logger.debug(log_msg, matched_acl)
 //            return

 //        acl_authorized = self._authorize_unconfirmed_identity(req, obj,
 //                                                              referrers,
 //                                                              roles)
 //        if acl_authorized:
 //            return

 //        # Check if a user tries to access an account that does not match their
 //        # token
 //        if not self._account_matches_tenant(account, tenant_id):
 //            log_msg = 'tenant mismatch: %s != %s'
 //            self.logger.debug(log_msg, account, tenant_id)
 //            return self.denied_response(req)

 //        # Compare roles from tokens against the configuration options:
 //        #
 //        # X-Auth-Token role  Has specified  X-Service-Token role  Grant
 //        # in operator_roles? service_roles? in service_roles?     swift_owner?
 //        # ------------------ -------------- --------------------  ------------
 //        # yes                yes            yes                   yes
 //        # yes                yes            no                    no
 //        # yes                no             don't care            yes
 //        # no                 don't care     don't care            no
 //        # ------------------ -------------- --------------------  ------------
 //        account_prefix = self._get_account_prefix(account)
 //        operator_roles = self.account_rules[account_prefix]['operator_roles']
 //        have_operator_role = set(operator_roles).intersection(
 //            set(user_roles))
 //        service_roles = self.account_rules[account_prefix]['service_roles']
 //        have_service_role = set(service_roles).intersection(
 //            set(user_service_roles))
 //        allowed = False
 //        if have_operator_role and (service_roles and have_service_role):
 //            allowed = True
 //        elif have_operator_role and not service_roles:
 //            allowed = True
 //        if allowed:
 //            log_msg = 'allow user with role(s) %s as account admin'
 //            self.logger.debug(log_msg, ','.join(have_operator_role.union(
 //                                                have_service_role)))
 //            req.environ['swift_owner'] = True
 //            return

 //        if acl_authorized is not None:
 //            return self.denied_response(req)

 //        # Check if we have the role in the userroles and allow it
 //        for user_role in user_roles:
 //            if user_role in (r.lower() for r in roles):
 //                log_msg = 'user %s:%s allowed in ACL: %s authorizing'
 //                self.logger.debug(log_msg, tenant_name, user_name,
 //                                  user_role)
 //                return

 //        return self.denied_response(req)
}


func (ka *keystoneAuth) getAccountPrefix(account string) (string, bool) {
	// Empty prefix matches everything, so try to match others first
	for prefix := range ka.resellerPrefixes {
		if prefix != "" and strings.HasPrefix(account, prefix) {
			return prefix, true
		}
	}
	for prefix := range ka.resellerPrefixes {
		if prefix == "" {
			return "", true
		}
	}
	return "", false
}

func (ka *keystoneAuth) authorizeAnonymous(r *http.Request) bool {
	pathParts, err := common.ParseProxyPath(r.URL.Path)
	if err != nil {
		srv.StandardResponse(writer, 404)
		return
	}
	// allow OPTIONS requests to proceed as normal
	if r.Method == "OPTIONS" {
		return true
	}
	isAuthorized := false
	if pathParts["account"] != "" {
		if prefix, ok := ka.getAccountPrefix(pathParts["account"]); ok{
			if common.StringInSlice(prefix, ka.resellerPrefixes) {
				isAuthorized = true
			}
		}
	}
	if !isAuthorized {
		srv.StandardResponse(writer, 401)
		return
	}
	ctx := GetProxyContext(r)
	referrers, roles := ParseACL(ctx.ACL)
    isAuthorized = ka.authorizeUnconfirmedIdentity(r, pathParts, referrers, roles)

    if !isAuthorized {
		srv.StandardResponse(writer, 401)
		return
	}
}

func (ka *keystoneAuth) authorizeUnconfirmedIdentity(r *http.Request, pathParts map[string]string, referrers []string, roles []string ) bool{
	ctx := GetProxyContext(r)
	// Allow container Sync
	if ci := ctx.GetContainerInfo(pathParts["account"], pathParts["container"]); ci != nil {
		if ci.SyncKey == r.Header.Get("X-Container-Sync-Key") && r.Header.Get("X-Timestamp") != "" {
			return true
		}
	}
	if ReferrerAllowed(r.Referer(), referrerACL){
		if pathParts["obj"] != "" || common.StringInSlice(".rlistings", roles) {
			return true
		}
	}
	return false
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
