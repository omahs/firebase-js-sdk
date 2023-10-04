/**
 * @license
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { Auth } from '../../model/public_types';

import {
  Endpoint,
  HttpMethod,
  _addTidIfNecessary,
  _performApiRequest
} from '../index';
import { IdTokenResponse } from '../../model/id_token';

export interface AuthenticatorAuthenticationResponse {
  credentialId: Uint8Array;
  credentialType?: string;
  authenticatorAssertionResponse: AuthenticatorAssertionResponse;
}

export interface AuthenticatorRegistrationResponse {
  credentialId: Uint8Array;
  credentialType?: string;
  authenticatorAttestationResponse: AuthenticatorAttestationResponse;
}

// Enrollment types.
export interface StartPasskeyEnrollmentRequest {
  idToken?: string;
  tenantId?: string;
}

export interface StartPasskeyEnrollmentResponse {
  credentialCreationOptions?: PublicKeyCredentialCreationOptions;
}

export async function startPasskeyEnrollment(
  auth: Auth,
  request: StartPasskeyEnrollmentRequest
): Promise<StartPasskeyEnrollmentResponse> {
  return _performApiRequest<
    StartPasskeyEnrollmentRequest,
    StartPasskeyEnrollmentResponse
  >(
    auth,
    HttpMethod.POST,
    Endpoint.START_PASSKEY_ENROLLMENT,
    _addTidIfNecessary(auth, request)
  );
}

export interface FinalizePasskeyEnrollmentRequest {
  idToken?: string;
  tenantId?: string;
  registrationResponse?: PublicKeyCredential;
}

export interface FinalizePasskeyEnrollmentResponse extends IdTokenResponse {
  localId: string;
  idToken?: string;
  refreshToken?: string;
}

export async function finalizePasskeyEnrollment(
  auth: Auth,
  request: FinalizePasskeyEnrollmentRequest
): Promise<FinalizePasskeyEnrollmentResponse> {
  return _performApiRequest<
    FinalizePasskeyEnrollmentRequest,
    FinalizePasskeyEnrollmentResponse
  >(
    auth,
    HttpMethod.POST,
    Endpoint.FINALIZE_PASSKEY_ENROLLMENT,
    _addTidIfNecessary(auth, request)
  );
}

// Sign-in types.
export interface StartPasskeySigninRequest {
  sessionId?: string;
  tenantId?: string;
}

export interface StartPasskeySigninResponse extends IdTokenResponse {
  credentialRequestOptions: PublicKeyCredentialRequestOptions;
}

export async function startPasskeySignin(
  auth: Auth,
  request: StartPasskeySigninRequest
): Promise<StartPasskeySigninResponse> {
  return _performApiRequest<
    StartPasskeySigninRequest,
    StartPasskeySigninResponse
  >(
    auth,
    HttpMethod.POST,
    Endpoint.START_PASSKEY_SIGNIN,
    _addTidIfNecessary(auth, request)
  );
}

export interface FinalizePasskeySigninRequest {
  authenticatorAuthenticationResponse?: AuthenticatorAuthenticationResponse;
  sessionId?: Uint8Array;
  tenantId?: string;
}

export interface FinalizePasskeySigninResponse extends IdTokenResponse {
  idToken?: string;
  refreshToken?: string;
}

export async function finalizePasskeySignin(
  auth: Auth,
  request: FinalizePasskeySigninRequest
): Promise<FinalizePasskeySigninResponse> {
  return _performApiRequest<
    FinalizePasskeySigninRequest,
    FinalizePasskeySigninResponse
  >(
    auth,
    HttpMethod.POST,
    Endpoint.FINALIZE_PASSKEY_SIGNIN,
    _addTidIfNecessary(auth, request)
  );
}
