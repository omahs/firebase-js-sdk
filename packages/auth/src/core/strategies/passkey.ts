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

import { Auth, User, UserCredential } from '../../model/public_types';

import {
  startPasskeyEnrollment,
  StartPasskeyEnrollmentRequest,
  StartPasskeyEnrollmentResponse,
  finalizePasskeyEnrollment,
  FinalizePasskeyEnrollmentRequest,
  FinalizePasskeyEnrollmentResponse,
  startPasskeySignIn,
  StartPasskeySignInRequest,
  StartPasskeySignInResponse,
  finalizePasskeySignIn,
  FinalizePasskeySignInRequest,
  FinalizePasskeySignInResponse,
  publicKeyCredentialToJSON
} from '../../api/account_management/passkey';
import { UserInternal } from '../../model/user';
import { _castAuth } from '../auth/auth_impl';
import { getModularInstance } from '@firebase/util';
import { OperationType } from '../../model/enums';
import { UserCredentialImpl } from '../user/user_credential_impl';
import { signInAnonymously } from './anonymous';

export async function signInWithPasskey(
  auth: Auth,
  name: string,
  manualSignUp: boolean = false
): Promise<UserCredential> {
  const authInternal = _castAuth(auth);

  // Start Passkey Sign in
  const startSignInRequest: StartPasskeySignInRequest = {};
  const startSignInResponse = await startPasskeySignIn(
    authInternal,
    startSignInRequest
  );

  const options = getPasskeyCredentialRequestOptions(startSignInResponse, name);

  // Get the crendential
  let credential;
  try {
    credential = (await navigator.credentials.get({
      publicKey: options
    })) as PublicKeyCredential;

    const finalizeSignInRequest: FinalizePasskeySignInRequest = {
      authenticatorAuthenticationResponse:
        publicKeyCredentialToJSON(credential),
      name,
      displayName: name
    };
    const finalizeSignInResponse = await finalizePasskeySignIn(
      authInternal,
      finalizeSignInRequest
    );

    const operationType = OperationType.SIGN_IN;
    const userCredential = await UserCredentialImpl._fromIdTokenResponse(
      authInternal,
      operationType,
      finalizeSignInResponse
    );
    await auth.updateCurrentUser(userCredential.user);
    return userCredential;
  } catch (error) {
    if (
      (error as Error).message.includes(
        'The operation either timed out or was not allowed.'
      ) &&
      !manualSignUp
    ) {
      // If the user is not signed up, sign them up anonymously
      const userCredential = await signInAnonymously(authInternal);
      const user = userCredential.user;
      return enrollPasskey(user, name);
    }
    return Promise.reject(error);
  }
}

/**
 * Links the user account with the given phone number.
 *
 * @param user - The user.
 *
 * @public
 */
export async function enrollPasskey(
  user: User,
  name: string
): Promise<UserCredential> {
  const userInternal = getModularInstance(user) as UserInternal;
  const authInternal = _castAuth(userInternal.auth);

  if (name === '') {
    name = 'Unnamed account (Web)';
  }

  // Start Passkey Enrollment
  const idToken = await userInternal.getIdToken();
  const startEnrollmentRequest: StartPasskeyEnrollmentRequest = {
    idToken
  };
  const startEnrollmentResponse = await startPasskeyEnrollment(
    authInternal,
    startEnrollmentRequest
  );

  // Create the crendential
  try {
    const options = getPasskeyCredentialCreationOptions(
      startEnrollmentResponse,
      name
    );
    const credential = (await navigator.credentials.create({
      publicKey: options
    })) as PublicKeyCredential;
    const idToken = await userInternal.getIdToken();
    const finalizeEnrollmentRequest: FinalizePasskeyEnrollmentRequest = {
      idToken,
      authenticatorRegistrationResponse: publicKeyCredentialToJSON(credential),
      name,
      displayName: name
    };
    const finalizeEnrollmentResponse = await finalizePasskeyEnrollment(
      authInternal,
      finalizeEnrollmentRequest
    );

    const operationType = OperationType.LINK;
    const userCredential = await UserCredentialImpl._fromIdTokenResponse(
      userInternal.auth,
      operationType,
      finalizeEnrollmentResponse
    );
    return userCredential;
  } catch (err) {
    return Promise.reject(err);
  }
}

function getPasskeyCredentialCreationOptions(
  response: StartPasskeyEnrollmentResponse,
  name: string = ''
): PublicKeyCredentialCreationOptions {
  const options = response.credentialCreationOptions!;
  const encoder = new TextEncoder();

  if (name === '') {
    name = 'Unnamed account (Web)';
  }

  options.user!.name = name;
  options.user!.displayName = name;
  options.user!.id = encoder.encode(
    options.user.id as unknown as string
  ).buffer;

  const rpId = window.location.hostname;
  options.rp!.id = rpId;
  options.rp!.name = rpId;

  const challengeBase64 = options.challenge as unknown as string;
  options.challenge = Uint8Array.from(atob(challengeBase64), c =>
    c.charCodeAt(0)
  );

  return options;
}

function getPasskeyCredentialRequestOptions(
  response: StartPasskeySignInResponse,
  name: string = ''
): PublicKeyCredentialRequestOptions {
  const options = response.credentialRequestOptions!;
  const encoder = new TextEncoder();

  if (name === '') {
    name = 'Unnamed account (Web)';
  }

  const rpId = window.location.hostname;
  options.rpId = rpId;
  options.challenge = encoder.encode(
    options.challenge as unknown as string
  ).buffer;

  return options;
}

// Debugging
export async function debugCreateCredential(
  name: string,
  debugStartPasskeyEnrollmentResponse: StartPasskeyEnrollmentResponse
): Promise<PublicKeyCredential> {
  const options = getPasskeyCredentialCreationOptions(
    debugStartPasskeyEnrollmentResponse,
    name
  );
  const credential = (await navigator.credentials.create({
    publicKey: options
  })) as PublicKeyCredential;
  return credential;
}

export async function debugGetCredential(
  name: string,
  debugStartPasskeySignInResponse: StartPasskeySignInResponse
): Promise<PublicKeyCredential> {
  const options = getPasskeyCredentialRequestOptions(
    debugStartPasskeySignInResponse,
    name
  );
  const credential = (await navigator.credentials.get({
    publicKey: options
  })) as PublicKeyCredential;
  return credential;
}

export async function debugPrepareStartPasskeyEnrollmentRequest(
  user: User
): Promise<StartPasskeyEnrollmentRequest> {
  const userInternal = getModularInstance(user) as UserInternal;
  const idToken = await userInternal.getIdToken();
  return {
    idToken
  };
}

export async function debugGetStartPasskeyEnrollmentResponse(
  user: User,
  request: StartPasskeyEnrollmentRequest
): Promise<StartPasskeyEnrollmentResponse> {
  const userInternal = getModularInstance(user) as UserInternal;
  const authInternal = _castAuth(userInternal.auth);
  return startPasskeyEnrollment(authInternal, request);
}

export async function debugPrepareFinalizePasskeyEnrollmentRequest(
  user: User,
  name: string,
  credential: PublicKeyCredential
): Promise<FinalizePasskeyEnrollmentRequest> {
  const userInternal = getModularInstance(user) as UserInternal;
  const idToken = await userInternal.getIdToken();
  return {
    idToken,
    authenticatorRegistrationResponse: publicKeyCredentialToJSON(credential),
    name
  };
}

export async function debugGetFinalizePasskeyEnrollmentResponse(
  user: User,
  request: FinalizePasskeyEnrollmentRequest
): Promise<FinalizePasskeyEnrollmentResponse> {
  const userInternal = getModularInstance(user) as UserInternal;
  const authInternal = _castAuth(userInternal.auth);
  return finalizePasskeyEnrollment(authInternal, request);
}

export async function debugPrepareStartPasskeySignInRequest(): Promise<StartPasskeySignInRequest> {
  return {};
}

export async function debugGetStartPasskeySignInResponse(
  auth: Auth,
  request: StartPasskeySignInRequest
): Promise<StartPasskeySignInResponse> {
  const authInternal = _castAuth(auth);
  return startPasskeySignIn(authInternal, request);
}

export async function debugPrepareFinalizePasskeySignInRequest(
  credential: PublicKeyCredential
): Promise<FinalizePasskeySignInRequest> {
  return {
    authenticatorAuthenticationResponse: publicKeyCredentialToJSON(credential)
  };
}

export async function debugGetFinalizePasskeySignInResponse(
  auth: Auth,
  request: FinalizePasskeySignInRequest
): Promise<FinalizePasskeySignInResponse> {
  const authInternal = _castAuth(auth);
  return finalizePasskeySignIn(authInternal, request);
}
