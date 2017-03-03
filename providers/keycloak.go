package providers

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

)
//This provider is based on google.go provider.
//Removed specifics for google group checks.
//Implement equivalent for Keycloak todo.

type KeycloakProvider struct {
	*ProviderData
}

func NewKeycloakProvider(p *ProviderData) *KeycloakProvider {
 	const myKeyCloakHost string = "keycloak.domain.local" //replace with the fqdn keycloak server
	const myKeyCloakRealm string = "default" //Replace with the keycloak realm string
	p.ProviderName = "Keycloak"
	if p.LoginURL.String() == "" {
		p.LoginURL = &url.URL{Scheme: "https",
			Host: myKeyCloakHost,
			Path: "/auth/realms/" + myKeyCloakRealm + "/protocol/openid-connect/auth",
			// to get a refresh token. see https://developers.google.com/identity/protocols/OAuth2WebServer#offline
			//RawQuery: "access_type=offline",
		}
	}
	if p.RedeemURL.String() == "" {
		p.RedeemURL = &url.URL{Scheme: "https",
			Host: myKeyCloakHost,
			Path: "/auth/realms/" + myKeyCloakRealm + "/protocol/openid-connect/token"}
	}
	if p.ValidateURL.String() == "" {
		p.ValidateURL = &url.URL{Scheme: "https",
			Host: myKeyCloakHost,
      Path: "/auth/realms/" + myKeyCloakRealm + "/protocol/openid-connect/userinfo"}
	}
	if p.Scope == "" {
		p.Scope = "profile email"
	}

	return &KeycloakProvider{
		ProviderData: p,
	}
}

func emailFromIdTokenK(idToken string) (string, error) {
	// Take from Google provider. Disabled verified email checks for default Keycloak use.
	// id_token is a base64 encode ID token payload
	jwt := strings.Split(idToken, ".")
	b, err := jwtDecodeSegmentK(jwt[1])
	if err != nil {
		return "", err
	}

	var email struct {
		Email         string `json:"email"`
//		EmailVerified bool   `json:"email_verified"`
	}
	err = json.Unmarshal(b, &email)
	if err != nil {
		return "", err
	}
	if email.Email == "" {
		return "", errors.New("missing email")
	}
//	if !email.EmailVerified {
//		return "", fmt.Errorf("email %s not listed as verified", email.Email)
//	}
	return email.Email, nil
}

func jwtDecodeSegmentK(seg string) ([]byte, error) {
	if l := len(seg) % 4; l > 0 {
		seg += strings.Repeat("=", 4-l)
	}

	return base64.URLEncoding.DecodeString(seg)
}

func (p *KeycloakProvider) Redeem(redirectURL, code string) (s *SessionState, err error) {
	if code == "" {
		err = errors.New("missing code")
		return
	}

	params := url.Values{}
	params.Add("redirect_uri", redirectURL)
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", p.ClientSecret)
	params.Add("code", code)
	params.Add("grant_type", "authorization_code")
	var req *http.Request
	req, err = http.NewRequest("POST", p.RedeemURL.String(), bytes.NewBufferString(params.Encode()))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	var body []byte
	body, err = ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return
	}

	if resp.StatusCode != 200 {
		err = fmt.Errorf("got %d from %q %s", resp.StatusCode, p.RedeemURL.String(), body)
		return
	}

	var jsonResponse struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
		IdToken      string `json:"id_token"`
	}
	err = json.Unmarshal(body, &jsonResponse)
	if err != nil {
		return
	}
	var email string
	email, err = emailFromIdTokenK(jsonResponse.IdToken)
	if err != nil {
		return
	}
	s = &SessionState{
		AccessToken:  jsonResponse.AccessToken,
		ExpiresOn:    time.Now().Add(time.Duration(jsonResponse.ExpiresIn) * time.Second).Truncate(time.Second),
		RefreshToken: jsonResponse.RefreshToken,
		Email:        email,
	}
	return
}

func (p *KeycloakProvider) RefreshSessionIfNeeded(s *SessionState) (bool, error) {
	if s == nil || s.ExpiresOn.After(time.Now()) || s.RefreshToken == "" {
		return false, nil
	}

	newToken, duration, err := p.redeemRefreshToken(s.RefreshToken)
	if err != nil {
		return false, err
	}

	origExpiration := s.ExpiresOn
	s.AccessToken = newToken
	s.ExpiresOn = time.Now().Add(duration).Truncate(time.Second)
	log.Printf("refreshed access token %s (expired on %s)", s, origExpiration)
	return true, nil
}


func (p *KeycloakProvider) redeemRefreshToken(refreshToken string) (token string, expires time.Duration, err error) {
	params := url.Values{}
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", p.ClientSecret)
	params.Add("refresh_token", refreshToken)
	params.Add("grant_type", "refresh_token")
	var req *http.Request
	req, err = http.NewRequest("POST", p.RedeemURL.String(), bytes.NewBufferString(params.Encode()))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	var body []byte
	body, err = ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return
	}

	if resp.StatusCode != 200 {
		err = fmt.Errorf("got %d from %q %s", resp.StatusCode, p.RedeemURL.String(), body)
		return
	}

	var data struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	err = json.Unmarshal(body, &data)
	if err != nil {
		return
	}
	token = data.AccessToken
	expires = time.Duration(data.ExpiresIn) * time.Second
	return
}

func (p *KeycloakProvider) ValidateGroup(email string) bool {
        return true
}

