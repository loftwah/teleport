/**
 * Copyright 2021 Gravitational, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package auth

import (
	"context"
	"net/mail"
	"strings"

	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/types"
	apievents "github.com/gravitational/teleport/api/types/events"
	apiutils "github.com/gravitational/teleport/api/utils"
	"github.com/gravitational/teleport/lib/auth/u2f"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/modules"
	"github.com/gravitational/teleport/lib/services"

	"github.com/gravitational/trace"
	"github.com/sethvargo/go-diceware/diceware"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

const (
	numOfRecoveryCodes     = 3
	numWordsInRecoveryCode = 8
	// accountLockedMsg is the reason used to update a user's status locked message.
	accountLockedMsg = "user has exceeded maximum failed account recovery attempts"
)

// fakeRecoveryCodeHash is bcrypt hash for "fake-barbaz x 8"
var fakeRecoveryCodeHash = []byte(`$2a$10$c2.h4pF9AA25lbrWo6U0D.ZmnYpFDaNzN3weNNYNC3jAkYEX9kpzu`)

// ErrMaxFailedRecoveryAttempts is a user friendly error message to notify user that recovery attempt
// has been temporarily locked and an email has been sent.
var ErrMaxFailedRecoveryAttempts = trace.AccessDenied("too many incorrect attempts, please check your email and try again later")

// CreateAccountRecoveryStartToken implements AuthService.CreateAccountRecoveryStartToken.
func (s *Server) CreateAccountRecoveryStartToken(ctx context.Context, req *proto.CreateAccountRecoveryStartTokenRequest) (types.UserToken, error) {
	if err := s.isAccountRecoveryAllowed(ctx); err != nil {
		return nil, trace.Wrap(err)
	}

	// Only user's with email as their username can start recovery.
	if _, err := mail.ParseAddress(req.GetUsername()); err != nil {
		return nil, trace.BadParameter("only emails as usernames are allowed to recover their account")
	}

	if err := s.verifyCodeWithRecoveryLock(ctx, req.GetUsername(), req.GetRecoveryCode()); err != nil {
		return nil, trace.Wrap(err)
	}

	// Remove any other existing tokens for this user before creating a token.
	if err := s.deleteUserTokens(ctx, req.Username); err != nil {
		return nil, trace.Wrap(err)
	}

	token, err := s.createRecoveryToken(ctx, req.GetUsername(), UserTokenTypeRecoveryStart, req.GetRecoverType())
	return token, trace.Wrap(err)
}

// verifyCodeWithRecoveryLock counts number of failed attempts at providing a valid recovery code.
// After MaxAccountRecoveryAttempts, user is temporarily locked from further attempts at recovering and locked from
// logging in. This functions similar to WithUserLock.
func (s *Server) verifyCodeWithRecoveryLock(ctx context.Context, username string, recoveryCode []byte) error {
	user, err := s.Identity.GetUser(username, false)
	if err != nil {
		if trace.IsNotFound(err) {
			// If user is not found, still authenticate. It should
			// always return an error. This prevents username oracles and
			// timing attacks.
			return s.verifyRecoveryCode(ctx, username, recoveryCode)
		}
		return trace.Wrap(err)
	}

	status := user.GetStatus()
	if status.IsLocked && status.RecoveryAttemptLockExpires.After(s.clock.Now().UTC()) {
		log.Debugf("%v exceeds %v failed account recovery attempts, locked until %v",
			user.GetName(), defaults.MaxAccountRecoveryAttempts, apiutils.HumanTimeFormat(status.RecoveryAttemptLockExpires))
		return trace.AccessDenied("too many incorrect recovery attempts, please try again later")
	}

	fnErr := s.verifyRecoveryCode(ctx, username, recoveryCode)
	if fnErr == nil {
		return nil
	}

	// Do not lock user in case if DB is flaky or down.
	if trace.IsConnectionProblem(fnErr) {
		return trace.Wrap(fnErr)
	}

	// Log failed attempt.
	now := s.clock.Now().UTC()
	attempt := types.RecoveryAttempt{Time: now, Expires: now.Add(defaults.AttemptTTL)}
	if err := s.CreateUserRecoveryAttempt(ctx, username, attempt); err != nil {
		log.Error(trace.DebugReport(err))
		return trace.Wrap(fnErr)
	}

	attempts, err := s.Identity.GetUserRecoveryAttempts(ctx, username)
	if err != nil {
		log.Error(trace.DebugReport(err))
		return trace.Wrap(fnErr)
	}

	if !types.IsMaxFailedRecoveryAttempt(defaults.MaxAccountRecoveryAttempts, attempts, now) {
		log.Debugf("%v user has less than %v failed account recovery attempts", username, defaults.MaxAccountRecoveryAttempts)
		return trace.Wrap(fnErr)
	}

	// Reached max attempts.
	lockUntil := s.clock.Now().UTC().Add(defaults.AccountLockInterval)

	log.Debugf("%v exceeds %v failed account recovery attempts, account locked until %v and an email has been sent",
		username, defaults.MaxAccountRecoveryAttempts, apiutils.HumanTimeFormat(lockUntil))

	// Temp lock both user login and recovery attempts.
	user.SetLockedFromRecoveryAttempt(lockUntil)
	user.SetLocked(lockUntil, accountLockedMsg)

	if err := s.Identity.UpsertUser(user); err != nil {
		log.Error(trace.DebugReport(err))
		return trace.Wrap(fnErr)
	}

	return ErrMaxFailedRecoveryAttempts
}

func (s *Server) verifyRecoveryCode(ctx context.Context, user string, givenCode []byte) error {
	recovery, err := s.GetRecoveryCodes(ctx, user)
	if err != nil && !trace.IsNotFound(err) {
		return trace.Wrap(err)
	}

	var hashedCodes []types.RecoveryCode
	userFound := true
	if trace.IsNotFound(err) {
		userFound = false
		log.Debugf("Account recovery codes for user %q not found, using fake hashes to mitigate timing attacks.", user)
		hashedCodes = []types.RecoveryCode{{Value: fakeRecoveryCodeHash}, {Value: fakeRecoveryCodeHash}, {Value: fakeRecoveryCodeHash}}
	} else {
		hashedCodes = recovery.GetCodes()
	}

	codeMatch := false
	for i, code := range hashedCodes {
		if err := bcrypt.CompareHashAndPassword(code.Value, givenCode); err == nil {
			if !code.IsUsed && userFound {
				codeMatch = true
				// Mark matched token as used in backend so it can't be used again.
				recovery.GetCodes()[i].IsUsed = true
				if err := s.UpsertRecoveryCodes(ctx, user, *recovery); err != nil {
					log.Error(trace.DebugReport(err))
					return trace.Wrap(err)
				}
				break
			}
		}
	}

	event := &apievents.RecoveryCodeUsed{
		Metadata: apievents.Metadata{
			Type: events.RecoveryCodeUsedEvent,
			Code: events.RecoveryCodeUsedCode,
		},
		UserMetadata: apievents.UserMetadata{
			User: user,
		},
		Status: apievents.Status{
			Success: true,
		},
	}

	if !codeMatch || !userFound {
		event.Status.Success = false
		event.Metadata.Code = events.RecoveryCodeUsedFailureCode
		traceErr := trace.NotFound("user not found")

		if userFound {
			traceErr = trace.BadParameter("recovery code did not match")
		}

		event.Status.Error = traceErr.Error()
		event.Status.UserMessage = traceErr.Error()

		if err := s.emitter.EmitAuditEvent(s.closeCtx, event); err != nil {
			log.WithFields(logrus.Fields{"user": user}).Warn("Failed to emit account recovery code used failed event.")
		}

		return trace.BadParameter("invalid username or recovery code")
	}

	if err := s.emitter.EmitAuditEvent(s.closeCtx, event); err != nil {
		log.WithFields(logrus.Fields{"user": user}).Warn("Failed to emit account recovery code used event.")
	}

	return nil
}

// CreateAccountRecoveryApprovedToken implements AuthService.CreateAccountRecoveryApprovedToken.
func (s *Server) CreateAccountRecoveryApprovedToken(ctx context.Context, req *proto.CreateAccountRecoveryApprovedTokenRequest) (types.UserToken, error) {
	if err := s.isAccountRecoveryAllowed(ctx); err != nil {
		return nil, trace.Wrap(err)
	}

	token, err := s.getRecoveryStartToken(ctx, req.GetRecoveryStartTokenID())
	if err != nil {
		if trace.IsNotFound(err) {
			return nil, trace.BadParameter("invalid token, please start over with a new recovery code")
		}
		return nil, trace.Wrap(err)
	}

	if token.GetUser() != req.Username {
		return nil, trace.BadParameter("username does not match")
	}

	if req.GetPassword() != nil {
		if token.GetUsage() == types.UserTokenUsage_RECOVER_PWD {
			return nil, trace.BadParameter("unexpected password credential")
		}

		token, err := s.verifyUserCredWithRecoveryLock(ctx, token, func() error {
			return s.checkPasswordWOToken(token.GetUser(), req.GetPassword())
		})

		return token, trace.Wrap(err)
	}

	if req.GetMFAAuthenticateResponse().GetTOTP() != nil {
		if token.GetUsage() == types.UserTokenUsage_RECOVER_2FA {
			return nil, trace.BadParameter("unexpected second factor credential")
		}

		token, err := s.verifyUserCredWithRecoveryLock(ctx, token, func() error {
			_, err := s.checkOTP(token.GetUser(), req.GetMFAAuthenticateResponse().GetTOTP().GetCode())
			return err
		})

		return token, trace.Wrap(err)
	}

	if req.GetMFAAuthenticateResponse().GetU2F() != nil {
		if token.GetUsage() == types.UserTokenUsage_RECOVER_2FA {
			return nil, trace.BadParameter("unexpected second factor credential")
		}

		token, err := s.verifyUserCredWithRecoveryLock(ctx, token, func() error {
			_, err := s.CheckU2FSignResponse(ctx, token.GetUser(), &u2f.AuthenticateChallengeResponse{
				KeyHandle:     req.GetMFAAuthenticateResponse().GetU2F().GetKeyHandle(),
				SignatureData: req.GetMFAAuthenticateResponse().GetU2F().GetSignature(),
				ClientData:    req.GetMFAAuthenticateResponse().GetU2F().GetClientData(),
			})

			return err
		})

		return token, trace.Wrap(err)
	}

	return nil, trace.BadParameter("at least one auth method required")
}

// verifyUserCredWithRecoveryLock counts number of failed attempts at providing a valid password or second factor.
// After max failed attempts, user's account is temporarily locked from logging in, and all user tokens is deleted.
func (s *Server) verifyUserCredWithRecoveryLock(ctx context.Context, token types.UserToken, authenticateFn func() error) (types.UserToken, error) {
	user, err := s.Identity.GetUser(token.GetUser(), false)
	if err != nil {
		if trace.IsNotFound(err) {
			// If user is not found, still call authenticateFn. It should
			// always return an error. This prevents username oracles and
			// timing attacks.
			return nil, authenticateFn()
		}
		return nil, trace.Wrap(err)
	}

	fnErr := authenticateFn()
	// If successfully authenticated, delete recovery attempts and initial recovery start token, and
	// return a new token marked approved for the final steps in recovery flow.
	if fnErr == nil {
		if err := s.DeleteUserToken(ctx, token.GetName()); err != nil {
			return nil, trace.Wrap(err)
		}

		if err := s.DeleteUserRecoveryAttempts(ctx, token.GetUser()); err != nil {
			return nil, trace.Wrap(err)
		}

		token, err := s.createRecoveryToken(ctx, token.GetUser(), UserTokenTypeRecoveryApproved, token.GetUsage())
		if err != nil {
			return nil, trace.Wrap(err)
		}

		return token, nil
	}

	// Do not lock user in case if DB is flaky or down.
	if trace.IsConnectionProblem(fnErr) {
		return nil, trace.Wrap(fnErr)
	}

	// Log failed attempt.
	now := s.clock.Now().UTC()
	attempt := types.RecoveryAttempt{Time: now, Expires: now.Add(defaults.AttemptTTL)}
	if err := s.CreateUserRecoveryAttempt(ctx, token.GetUser(), attempt); err != nil {
		log.Error(trace.DebugReport(err))
		return nil, trace.Wrap(fnErr)
	}

	attempts, err := s.Identity.GetUserRecoveryAttempts(ctx, token.GetUser())
	if err != nil {
		log.Error(trace.DebugReport(err))
		return nil, trace.Wrap(fnErr)
	}

	if !types.IsMaxFailedRecoveryAttempt(defaults.MaxAccountRecoveryAttempts, attempts, now) {
		log.Debugf("%v user has less than %v failed account recovery attempts", token.GetUser(), defaults.MaxAccountRecoveryAttempts)
		return nil, trace.Wrap(fnErr)
	}

	// Reached max attempts.
	lockUntil := s.clock.Now().UTC().Add(defaults.AccountLockInterval)

	log.Debugf("%v exceeds %v failed account recovery attempts, account locked until %v and an email has been sent",
		token.GetUser(), defaults.MaxAccountRecoveryAttempts, apiutils.HumanTimeFormat(lockUntil))

	// Delete all token data related to this user, to force user to restart the recovery flow.
	if err := s.deleteUserTokens(ctx, token.GetUser()); err != nil {
		log.Error(trace.DebugReport(err))
		return nil, trace.Wrap(fnErr)
	}

	// Restart the attempt counter.
	if err := s.DeleteUserRecoveryAttempts(ctx, token.GetUser()); err != nil {
		log.Error(trace.DebugReport(err))
		return nil, trace.Wrap(fnErr)
	}

	// Only lock the user from logging in.
	user.SetLocked(lockUntil, accountLockedMsg)
	if err := s.Identity.UpsertUser(user); err != nil {
		log.Error(trace.DebugReport(err))
		return nil, trace.Wrap(fnErr)
	}

	return nil, ErrMaxFailedRecoveryAttempts
}

// ChangeAuthenticationFromAccountRecovery implements AuthService.ChangeAuthenticationFromAccountRecovery.
func (s *Server) ChangeAuthenticationFromAccountRecovery(ctx context.Context, req *proto.ChangeAuthenticationFromAccountRecoveryRequest) error {
	if err := s.isAccountRecoveryAllowed(ctx); err != nil {
		return trace.Wrap(err)
	}

	token, err := s.getRecoveryApprovedToken(ctx, req.GetRecoveryApprovedTokenID())
	if err != nil {
		return trace.Wrap(err)
	}

	// Check that the correct auth credential is being recovered before setting a new one.
	switch token.GetUsage() {
	case types.UserTokenUsage_RECOVER_PWD:
		if req.GetNewPassword() == nil {
			return trace.BadParameter("expected a new password")
		}

		if err := services.VerifyPassword(req.GetNewPassword()); err != nil {
			return trace.Wrap(err)
		}

		if err := s.UpsertPassword(token.GetUser(), req.GetNewPassword()); err != nil {
			return trace.Wrap(err)
		}

	case types.UserTokenUsage_RECOVER_2FA:
		isDeviceCreated := false

		if req.GetNewMFAResponse().GetU2F() != nil {
			cap, err := s.GetAuthPreference(ctx)
			if err != nil {
				return trace.Wrap(err)
			}

			cfg, err := cap.GetU2F()
			if err != nil {
				return trace.Wrap(err)
			}

			if err := s.createNewU2FDevice(ctx, newU2FDeviceRequest{
				tokenID:    req.GetRecoveryApprovedTokenID(),
				username:   token.GetUser(),
				deviceName: req.GetNewDeviceName(),
				u2fRegisterResponse: u2f.RegisterChallengeResponse{
					RegistrationData: req.GetNewMFAResponse().GetU2F().GetRegistrationData(),
					ClientData:       req.GetNewMFAResponse().GetU2F().GetClientData(),
				},
				cfg: cfg,
			}); err != nil {
				return trace.Wrap(err)
			}
			isDeviceCreated = true
		}

		if req.GetNewMFAResponse().GetTOTP() != nil {
			if err := s.createNewTOTPDevice(ctx, newTOTPDeviceRequest{
				tokenID:           req.GetRecoveryApprovedTokenID(),
				username:          token.GetUser(),
				deviceName:        req.GetNewDeviceName(),
				secondFactorToken: req.GetNewMFAResponse().GetTOTP().Code,
			}); err != nil {
				return trace.Wrap(err)
			}
			isDeviceCreated = true
		}

		if !isDeviceCreated {
			return trace.BadParameter("expected a new mfa credential")
		}

	default:
		return trace.BadParameter("invalid recovery usage type")
	}

	// Check and remove user login lock so user can immediately sign in after recovering.
	user, err := s.GetUser(token.GetUser(), false)
	if err != nil {
		return trace.Wrap(err)
	}

	if user.GetStatus().IsLocked {
		user.ResetLocks()
		if err := s.Identity.UpsertUser(user); err != nil {
			return trace.Wrap(err)
		}

		if err := s.DeleteUserLoginAttempts(token.GetUser()); err != nil {
			return trace.Wrap(err)
		}
	}

	return nil
}

// CreateAccountRecoveryCodes implements AuthService.CreateAccountRecoveryCodes.
func (s *Server) CreateAccountRecoveryCodes(ctx context.Context, req *proto.CreateAccountRecoveryCodesRequest) (*proto.CreateAccountRecoveryCodesResponse, error) {
	if err := s.isAccountRecoveryAllowed(ctx); err != nil {
		return nil, trace.Wrap(err)
	}

	token, err := s.getRecoveryApprovedToken(ctx, req.GetRecoveryApprovedTokenID())
	if err != nil {
		return nil, trace.Wrap(err)
	}

	codes, err := s.generateAndUpsertRecoveryCodes(ctx, token.GetUser())
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Delete all token data related to this user, as this is the end of recovery.
	if err := s.deleteUserTokens(ctx, token.GetUser()); err != nil {
		log.Error(trace.DebugReport(err))
	}

	return &proto.CreateAccountRecoveryCodesResponse{
		RecoveryCodes: codes,
	}, nil
}

func (s *Server) generateAndUpsertRecoveryCodes(ctx context.Context, username string) ([]string, error) {
	tokens, err := generateRecoveryCodes()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	hashedTokens := make([]types.RecoveryCode, len(tokens))
	for i, token := range tokens {
		hashedToken, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
		if err != nil {
			return nil, trace.Wrap(err)
		}

		hashedTokens[i].Value = hashedToken
	}

	rc, err := types.NewRecoveryCodes(hashedTokens, s.GetClock().Now().UTC(), username)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if err := s.UpsertRecoveryCodes(ctx, username, *rc); err != nil {
		return nil, trace.Wrap(err)
	}

	if err := s.emitter.EmitAuditEvent(s.closeCtx, &apievents.RecoveryCodeGenerate{
		Metadata: apievents.Metadata{
			Type: events.RecoveryCodeGeneratedEvent,
			Code: events.RecoveryCodesGeneratedCode,
		},
		UserMetadata: apievents.UserMetadata{
			User: username,
		},
	}); err != nil {
		log.WithError(err).WithFields(logrus.Fields{"user": username}).Warn("Failed to emit recovery tokens generate event.")
	}

	return tokens, nil
}

// isAccountRecoveryAllowed gets cluster auth configuration and check if cloud, local auth
// and second factor is allowed, which are required for account recovery.
func (s *Server) isAccountRecoveryAllowed(ctx context.Context) error {
	if modules.GetModules().Features().Cloud == false {
		return trace.AccessDenied("account recovery is only available for enterprise cloud")
	}

	authPref, err := s.GetAuthPreference(ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	if !authPref.GetAllowLocalAuth() {
		return trace.AccessDenied("local auth needs to be enabled")
	}

	if !authPref.IsSecondFactorEnforced() {
		return trace.AccessDenied("second factor must be enabled")
	}

	return nil
}

// generateRecoveryCodes returns an array of tokens where each token
// have 8 random words prefixed with tele and concanatenated with dashes.
func generateRecoveryCodes() ([]string, error) {
	gen, err := diceware.NewGenerator(nil)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	tokenList := make([]string, numOfRecoveryCodes)
	for i := 0; i < numOfRecoveryCodes; i++ {
		list, err := gen.Generate(numWordsInRecoveryCode)
		if err != nil {
			return nil, trace.Wrap(err)
		}

		tokenList[i] = "tele-" + strings.Join(list, "-")
	}

	return tokenList, nil
}
