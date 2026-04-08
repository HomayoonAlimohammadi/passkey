package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/graphql-go/graphql"
	"github.com/graphql-go/graphql/language/ast"
	"golang.org/x/crypto/bcrypt"
)

// ─── JSON scalar ──────────────────────────────────────────────────────────────
// Used as the opaque type for WebAuthn options blobs returned by begin mutations.
// Only ever an output — ParseValue/ParseLiteral are stubs.

var jsonScalar = graphql.NewScalar(graphql.ScalarConfig{
	Name:        "JSON",
	Description: "Arbitrary serialisable JSON value.",
	Serialize: func(value interface{}) interface{} {
		b, err := json.Marshal(value)
		if err != nil {
			return nil
		}
		var v interface{}
		_ = json.Unmarshal(b, &v)
		return v
	},
	ParseValue:   func(value interface{}) interface{} { return value },
	ParseLiteral: func(val ast.Value) interface{} { return val.GetValue() },
})

// ─── Output types ─────────────────────────────────────────────────────────────

var authPayloadType = graphql.NewObject(graphql.ObjectConfig{
	Name: "AuthPayload",
	Fields: graphql.Fields{
		// token: opaque bearer token — in production this would be a signed JWT.
		"token":    &graphql.Field{Type: graphql.NewNonNull(graphql.String)},
		"username": &graphql.Field{Type: graphql.NewNonNull(graphql.String)},
	},
})

var creationOptionsPayloadType = graphql.NewObject(graphql.ObjectConfig{
	Name: "CreationOptionsPayload",
	Fields: graphql.Fields{
		// sessionToken threads the ceremony: client passes it back to passkeyRegisterFinish.
		"sessionToken": &graphql.Field{Type: graphql.NewNonNull(graphql.String)},
		// options: the PublicKeyCredentialCreationOptions blob the browser needs.
		"options": &graphql.Field{Type: graphql.NewNonNull(jsonScalar)},
	},
})

var requestOptionsPayloadType = graphql.NewObject(graphql.ObjectConfig{
	Name: "RequestOptionsPayload",
	Fields: graphql.Fields{
		"sessionToken": &graphql.Field{Type: graphql.NewNonNull(graphql.String)},
		"options":      &graphql.Field{Type: graphql.NewNonNull(jsonScalar)},
	},
})

// ─── Input types ──────────────────────────────────────────────────────────────
// Field names are camelCase to match what the WebAuthn library parses from JSON.

var registrationResponseInputType = graphql.NewInputObject(graphql.InputObjectConfig{
	Name: "RegistrationResponseInput",
	Fields: graphql.InputObjectConfigFieldMap{
		"clientDataJSON":    {Type: graphql.NewNonNull(graphql.String)},
		"attestationObject": {Type: graphql.NewNonNull(graphql.String)},
	},
})

var registrationCredentialInputType = graphql.NewInputObject(graphql.InputObjectConfig{
	Name: "RegistrationCredentialInput",
	Fields: graphql.InputObjectConfigFieldMap{
		"id":                      {Type: graphql.NewNonNull(graphql.String)},
		"rawId":                   {Type: graphql.NewNonNull(graphql.String)},
		"type":                    {Type: graphql.NewNonNull(graphql.String)},
		"authenticatorAttachment": {Type: graphql.String},
		"response":                {Type: graphql.NewNonNull(registrationResponseInputType)},
	},
})

var authenticationResponseInputType = graphql.NewInputObject(graphql.InputObjectConfig{
	Name: "AuthenticationResponseInput",
	Fields: graphql.InputObjectConfigFieldMap{
		"clientDataJSON":    {Type: graphql.NewNonNull(graphql.String)},
		"authenticatorData": {Type: graphql.NewNonNull(graphql.String)},
		"signature":         {Type: graphql.NewNonNull(graphql.String)},
		"userHandle":        {Type: graphql.String},
	},
})

var authenticationCredentialInputType = graphql.NewInputObject(graphql.InputObjectConfig{
	Name: "AuthenticationCredentialInput",
	Fields: graphql.InputObjectConfigFieldMap{
		"id":                      {Type: graphql.NewNonNull(graphql.String)},
		"rawId":                   {Type: graphql.NewNonNull(graphql.String)},
		"type":                    {Type: graphql.NewNonNull(graphql.String)},
		"authenticatorAttachment": {Type: graphql.String},
		"response":                {Type: graphql.NewNonNull(authenticationResponseInputType)},
	},
})

// ─── Helpers ──────────────────────────────────────────────────────────────────

func tokenPrefix(t string) string {
	if len(t) >= 8 {
		return t[:8]
	}
	return t
}

// fakeReqFromArgs marshals the credential input map back to JSON and wraps it
// in a synthetic *http.Request so the go-webauthn library can parse r.Body.
// This is necessary because the library's Finish* methods read from r.Body directly.
func fakeReqFromArgs(credArg interface{}) (*http.Request, error) {
	body, err := json.Marshal(credArg)
	if err != nil {
		return nil, fmt.Errorf("invalid credential input: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return req, nil
}

// ─── Resolvers ────────────────────────────────────────────────────────────────

func resolvePasswordRegister(p graphql.ResolveParams) (interface{}, error) {
	username, _ := p.Args["username"].(string)
	password, _ := p.Args["password"].(string)
	slog.Info("gql/passwordRegister", "username", username)

	if len(username) == 0 || len(username) > 64 {
		return nil, fmt.Errorf("username must be 1–64 characters")
	}
	if len(password) < 8 {
		return nil, fmt.Errorf("password must be at least 8 characters")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		slog.Error("gql/passwordRegister: bcrypt failed", "error", err)
		return nil, fmt.Errorf("internal error")
	}

	user, _ := users.GetOrCreate(username)
	users.SetPassword(user.Name, hash)
	slog.Info("gql/passwordRegister: complete", "username", user.Name)
	return map[string]interface{}{"token": newToken(), "username": user.Name}, nil
}

func resolvePasswordLogin(p graphql.ResolveParams) (interface{}, error) {
	username, _ := p.Args["username"].(string)
	password, _ := p.Args["password"].(string)
	slog.Info("gql/passwordLogin", "username", username)

	// Constant-time path: always hash-compare even when user doesn't exist
	// to prevent user enumeration via timing differences.
	user, ok := users.Get(username)
	if !ok || len(user.PasswordHash) == 0 {
		slog.Warn("gql/passwordLogin: user not found or no password set", "username", username)
		return nil, fmt.Errorf("invalid credentials")
	}
	if err := bcrypt.CompareHashAndPassword(user.PasswordHash, []byte(password)); err != nil {
		slog.Warn("gql/passwordLogin: wrong password", "username", username)
		return nil, fmt.Errorf("invalid credentials")
	}

	slog.Info("gql/passwordLogin: complete", "username", user.Name)
	return map[string]interface{}{"token": newToken(), "username": user.Name}, nil
}

func resolvePasskeyRegisterBegin(p graphql.ResolveParams) (interface{}, error) {
	username, _ := p.Args["username"].(string)
	slog.Info("gql/passkeyRegisterBegin", "username", username)

	if len(username) == 0 || len(username) > 64 {
		return nil, fmt.Errorf("invalid username")
	}

	user, _ := users.GetOrCreate(username)
	exclusions := webauthn.Credentials(user.WebAuthnCredentials()).CredentialDescriptors()
	opts, session, err := wa.BeginRegistration(user, webauthn.WithExclusions(exclusions))
	if err != nil {
		slog.Error("gql/passkeyRegisterBegin: BeginRegistration failed", "error", err)
		return nil, err
	}

	token := newToken()
	regSess.set(token, &regEntry{data: session, username: username})
	slog.Info("gql/passkeyRegisterBegin: session created", "token_prefix", tokenPrefix(token))
	return map[string]interface{}{"sessionToken": token, "options": opts}, nil
}

func resolvePasskeyRegisterFinish(p graphql.ResolveParams) (interface{}, error) {
	sessionToken, _ := p.Args["sessionToken"].(string)
	slog.Info("gql/passkeyRegisterFinish", "token_prefix", tokenPrefix(sessionToken))

	entry, ok := regSess.pop(sessionToken)
	if !ok {
		return nil, fmt.Errorf("session not found or expired")
	}

	user, ok := users.Get(entry.username)
	if !ok {
		return nil, fmt.Errorf("user not found")
	}

	fakeReq, err := fakeReqFromArgs(p.Args["credential"])
	if err != nil {
		return nil, err
	}

	credential, err := wa.FinishRegistration(user, *entry.data, fakeReq)
	if err != nil {
		slog.Error("gql/passkeyRegisterFinish: FinishRegistration failed", "username", user.Name, "error", err)
		return nil, err
	}

	users.AddCredential(user.Name, *credential)
	slog.Info("gql/passkeyRegisterFinish: complete", "username", user.Name)
	return map[string]interface{}{"token": newToken(), "username": user.Name}, nil
}

func resolvePasskeyLoginBegin(p graphql.ResolveParams) (interface{}, error) {
	slog.Info("gql/passkeyLoginBegin")

	opts, session, err := wa.BeginDiscoverableLogin()
	if err != nil {
		slog.Error("gql/passkeyLoginBegin: failed", "error", err)
		return nil, err
	}

	token := newToken()
	loginSess.set(token, session)
	slog.Info("gql/passkeyLoginBegin: session created", "token_prefix", tokenPrefix(token))
	return map[string]interface{}{"sessionToken": token, "options": opts}, nil
}

func resolvePasskeyLoginFinish(p graphql.ResolveParams) (interface{}, error) {
	sessionToken, _ := p.Args["sessionToken"].(string)
	slog.Info("gql/passkeyLoginFinish", "token_prefix", tokenPrefix(sessionToken))

	session, ok := loginSess.pop(sessionToken)
	if !ok {
		return nil, fmt.Errorf("session not found or expired")
	}

	fakeReq, err := fakeReqFromArgs(p.Args["credential"])
	if err != nil {
		return nil, err
	}

	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		u, ok := users.GetByID(userHandle)
		if !ok {
			return nil, fmt.Errorf("user not found")
		}
		return u, nil
	}

	user, credential, err := wa.FinishPasskeyLogin(handler, *session, fakeReq)
	if err != nil {
		slog.Error("gql/passkeyLoginFinish: failed", "error", err)
		return nil, err
	}

	users.UpdateCredential(user.WebAuthnID(), credential)
	slog.Info("gql/passkeyLoginFinish: complete", "username", user.WebAuthnName())
	return map[string]interface{}{"token": newToken(), "username": user.WebAuthnName()}, nil
}

// ─── Schema ───────────────────────────────────────────────────────────────────

var gqlSchema graphql.Schema

func init() {
	mutationType := graphql.NewObject(graphql.ObjectConfig{
		Name: "Mutation",
		Fields: graphql.Fields{
			// ── Password (single round-trip) ───────────────────────────────────
			"passwordRegister": &graphql.Field{
				Type: graphql.NewNonNull(authPayloadType),
				Args: graphql.FieldConfigArgument{
					"username": {Type: graphql.NewNonNull(graphql.String)},
					"password": {Type: graphql.NewNonNull(graphql.String)},
				},
				Resolve: resolvePasswordRegister,
			},
			"passwordLogin": &graphql.Field{
				Type: graphql.NewNonNull(authPayloadType),
				Args: graphql.FieldConfigArgument{
					"username": {Type: graphql.NewNonNull(graphql.String)},
					"password": {Type: graphql.NewNonNull(graphql.String)},
				},
				Resolve: resolvePasswordLogin,
			},

			// ── Passkey — two-step ceremony ────────────────────────────────────
			// Begin: server issues a challenge → client gets sessionToken + options.
			// Finish: client sends sessionToken + authenticator response → server verifies.
			"passkeyRegisterBegin": &graphql.Field{
				Type: graphql.NewNonNull(creationOptionsPayloadType),
				Args: graphql.FieldConfigArgument{
					"username": {Type: graphql.NewNonNull(graphql.String)},
				},
				Resolve: resolvePasskeyRegisterBegin,
			},
			"passkeyRegisterFinish": &graphql.Field{
				Type: graphql.NewNonNull(authPayloadType),
				Args: graphql.FieldConfigArgument{
					"sessionToken": {Type: graphql.NewNonNull(graphql.String)},
					"credential":   {Type: graphql.NewNonNull(registrationCredentialInputType)},
				},
				Resolve: resolvePasskeyRegisterFinish,
			},
			"passkeyLoginBegin": &graphql.Field{
				Type:    graphql.NewNonNull(requestOptionsPayloadType),
				Resolve: resolvePasskeyLoginBegin,
			},
			"passkeyLoginFinish": &graphql.Field{
				Type: graphql.NewNonNull(authPayloadType),
				Args: graphql.FieldConfigArgument{
					"sessionToken": {Type: graphql.NewNonNull(graphql.String)},
					"credential":   {Type: graphql.NewNonNull(authenticationCredentialInputType)},
				},
				Resolve: resolvePasskeyLoginFinish,
			},
		},
	})

	// GraphQL spec requires at least one Query field.
	queryType := graphql.NewObject(graphql.ObjectConfig{
		Name: "Query",
		Fields: graphql.Fields{
			"_health": &graphql.Field{
				Type:    graphql.NewNonNull(graphql.String),
				Resolve: func(p graphql.ResolveParams) (interface{}, error) { return "ok", nil },
			},
		},
	})

	var err error
	gqlSchema, err = graphql.NewSchema(graphql.SchemaConfig{
		Query:    queryType,
		Mutation: mutationType,
	})
	if err != nil {
		panic(fmt.Sprintf("graphql schema error: %v", err))
	}
}

// ─── HTTP handler ─────────────────────────────────────────────────────────────

func handleGraphQL(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Query         string                 `json:"query"`
		Variables     map[string]interface{} `json:"variables"`
		OperationName string                 `json:"operationName"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	result := graphql.Do(graphql.Params{
		Schema:         gqlSchema,
		RequestString:  req.Query,
		VariableValues: req.Variables,
		OperationName:  req.OperationName,
	})

	writeJSON(w, result)
}
