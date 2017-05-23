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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/troubling/hummingbird/common/conf"
	"go.uber.org/zap"
)

type identity struct {
	client          *http.Client
	authURL         string
	authPlugin      string
	projectDomainID string
	userDomainID    string
	projectName     string
	userName        string
	password        string
	userAgent       string
}

type authToken struct {
	*identity
	next      http.Handler
	cacheTime int
}

var authHeaders = []string{"X-Identity-Status",
	"X-Service-Identity-Status",
	"X-Domain-Id",
	"X-Domain-Name",
	"X-Project-Id",
	"X-Project-Name",
	"X-Project-Domain-Id",
	"X-Project-Domain-Name",
	"X-User-Id",
	"X-User-Name",
	"X-User-Domain-Id",
	"X-User-Domain-Name",
	"X-Roles",
	"X-Service-Domain-Id",
	"X-Service-Domain-Name",
	"X-Service-Project-Id",
	"X-Service-Project-Name",
	"X-Service-Project-Domain-Id",
	"X-Service-Project-Domain-Name",
	"X-Service-User-Id",
	"X-Service-User-Name",
	"X-Service-User-Domain-Id",
	"X-Service-User-Domain-Name",
	"X-Service-Roles",
	"X-Service-Catalog",
	"X-Is-Admin-Project",
	//Deprecated Headers
	"X-Role",
	"X-User",
	"X-Tenant-Id",
	"X-Tenant-Name",
	"X-Tenant",
}

type domain struct {
	ID      string `json:"id"`
	Name    string `json:"name,omitempty"`
	Enabled bool   `json:"enabled,omitempty"`
}

type project struct {
	ID      string  `json:"id,omitempty"`
	Name    string  `json:"name,omitempty"`
	Enabled bool    `json:"enabled,omitempty"`
	Domain  *domain `json:"domain"`
}

type token struct {
	ExpiresAt time.Time `json:"expires_at"`
	IssuedAt  time.Time `json:"issued_at"`
	Methods   []string
	User      struct {
		ID      string
		Name    string
		Email   string
		Enabled bool
		Domain  struct {
			ID   string
			Name string
		}
	}
	Project *project
	Domain  *domain
	Roles   *[]struct {
		ID   string
		Name string
	}
}

func (t token) Valid() bool {
	now := time.Now().Unix()
	return t.IssuedAt.Unix() <= now && now < t.ExpiresAt.Unix()
}

func (t token) populateReqHeader(r *http.Request) {
	r.Header.Set("X-User-Id", t.User.ID)
	r.Header.Set("X-User-Name", t.User.Name)
	r.Header.Set("X-User-Domain-Id", t.User.Domain.ID)
	r.Header.Set("X-User-Domain-Name", t.User.Domain.Name)

	if project := t.Project; project != nil {
		r.Header.Set("X-Project-Name", project.Name)
		r.Header.Set("X-Project-Id", project.ID)
		r.Header.Set("X-Project-Domain-Name", project.Domain.Name)
		r.Header.Set("X-Project-Domain-Id", project.Domain.ID)
	}

	if domain := t.Domain; domain != nil {
		r.Header.Set("X-Domain-Id", domain.ID)
		r.Header.Set("X-Domain-Name", domain.Name)
	}

	if roles := t.Roles; roles != nil {
		roleNames := []string{}
		for _, role := range *t.Roles {
			roleNames = append(roleNames, role.Name)
		}
		r.Header.Set("X-Roles", strings.Join(roleNames, ","))
	}
}

type identityReq struct {
	Auth struct {
		Identity struct {
			Methods  []string `json:"methods"`
			Password struct {
				User struct {
					Domain struct {
						ID string `json:"id"`
					} `json:"domain"`
					Name     string `json:"name"`
					Password string `json:"password"`
				} `json:"user"`
			} `json:"password"`
		} `json:"identity"`

		Scope struct {
			Project *project `json:"project"`
		} `json:"scope"`
	} `json:"auth"`
}

type identityResponse struct {
	Error *struct {
		Code    int
		Message string
		Title   string
	}
	Token *token
}

func (at *authToken) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	removeAuthHeaders(r)
	r.Header.Set("X-Identity-Status", "Invalid")
	defer at.next.ServeHTTP(w, r)
	authToken := r.Header.Get("X-Auth-Token")
	if authToken == "" {
		authToken = r.Header.Get("X-Storage-Token")
		if authToken == "" {
			return
		}
	}
	var newToken *token
	ctx := GetProxyContext(r)
	if cachedToken, err := ctx.Cache.Get(authToken); err == nil {
		ctx.Logger.Debug("Found cache token",
			zap.String("token", authToken))
		if t, ok := cachedToken.(token); ok {
			newToken = &t
		}
	}

	if newToken == nil {
		var err error
		newToken, err = at.validate(authToken)
		if err != nil {
			ctx.Logger.Debug("Failed to validate token", zap.Error(err))
			return
		}
		ttl := at.cacheTime
		if expiresIn := newToken.ExpiresAt.Sub(time.Now()); expiresIn < time.Duration(at.cacheTime)*time.Second {
			ttl = int(expiresIn / time.Second)
		}
		ctx.Cache.Set(authToken, *newToken, ttl)
	}
	r.Header.Set("X-Identity-Status", "Confirmed")
	newToken.populateReqHeader(r)
}

func (at *authToken) validate(token string) (*token, error) {
	if !strings.HasSuffix(at.authURL, "/") {
		at.authURL += "/"
	}
	req, err := http.NewRequest("GET", at.authURL+"/auth/tokens?nocatalog", nil)
	if err != nil {
		return nil, err
	}
	serverAuthToken, err := at.serverAuth()
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Auth-Token", serverAuthToken)
	req.Header.Set("X-Subject-Token", token)
	req.Header.Set("User-Agent", at.userAgent)

	r, err := at.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	if r.StatusCode >= 400 {
		return nil, errors.New(r.Status)
	}

	var resp identityResponse
	if err = json.NewDecoder(r.Body).Decode(&resp); err != nil {
		return nil, err
	}

	if e := resp.Error; e != nil {
		return nil, fmt.Errorf("%s : %s", r.Status, e.Message)
	}
	if r.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s", r.Status)
	}
	if resp.Token == nil {
		return nil, errors.New("Response didn't contain token context")
	}
	if !resp.Token.Valid() {
		return nil, errors.New("Returned token is not valid")

	}
	return resp.Token, nil
}

// serverAuth return the X-Auth-Token to use or an error.
func (at *authToken) serverAuth() (string, error) {
	authReq := &identityReq{}
	authReq.Auth.Identity.Methods = []string{at.authPlugin}
	authReq.Auth.Identity.Password.User.Domain.ID = at.userDomainID
	authReq.Auth.Identity.Password.User.Name = at.userName
	authReq.Auth.Identity.Password.User.Password = at.password
	authReq.Auth.Scope.Project = &project{Domain: &domain{ID: at.projectDomainID}, Name: at.projectName}
	authReqBody, err := json.Marshal(authReq)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", at.authURL+"v3/auth/tokens", bytes.NewBuffer(authReqBody))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := at.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 201 {
		return "", fmt.Errorf("server auth token request gave status %d", resp.StatusCode)
	}
	rv := resp.Header.Get("X-Subject-Token")
	return rv, nil
}

func removeAuthHeaders(r *http.Request) {
	for _, header := range authHeaders {
		r.Header.Del(header)
	}
}

func NewAuthToken(config conf.Section) (func(http.Handler) http.Handler, error) {
	return func(next http.Handler) http.Handler {
		return &authToken{
			next:      next,
			cacheTime: int(config.GetInt("token_cache_time", 300)),
			identity: &identity{authURL: config.GetDefault("auth_uri", "http://127.0.0.1:5000/"),
				authPlugin:      config.GetDefault("auth_plugin", "password"),
				projectDomainID: config.GetDefault("project_domain_id", "default"),
				userDomainID:    config.GetDefault("user_domain_id", "default"),
				projectName:     config.GetDefault("project_name", "service"),
				userName:        config.GetDefault("username", "swift"),
				password:        config.GetDefault("password", "password"),
				userAgent:       config.GetDefault("user_agent", "hummingbird-keystone-middleware/1.0"),
				client: &http.Client{
					Timeout: 5 * time.Second,
				}},
		}
	}, nil
}
