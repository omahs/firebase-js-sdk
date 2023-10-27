/* eslint-disable @typescript-eslint/no-require-imports */
/**
 * @license
 * Copyright 2022 Google LLC
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

import { isEnterprise, RecaptchaConfig } from './recaptcha';
import { getRecaptchaConfig } from '../../api/authentication/recaptcha';
import {
  RecaptchaClientType,
  RecaptchaVersion,
  RecaptchaActionName,
  RecaptchaProvider,
  EnforcementState
} from '../../api';

import { Auth } from '../../model/public_types';
import { AuthInternal } from '../../model/auth';
import { _castAuth } from '../../core/auth/auth_impl';
import * as jsHelpers from '../load_js';
import { AuthErrorCode } from '../../core/errors';
import { StartPhoneMfaEnrollmentRequest } from '../../api/account_management/mfa';
import { StartPhoneMfaSignInRequest } from '../../api/authentication/mfa';

const RECAPTCHA_ENTERPRISE_URL =
  'https://www.google.com/recaptcha/enterprise.js?render=';

export const RECAPTCHA_ENTERPRISE_VERIFIER_TYPE = 'recaptcha-enterprise';
export const FAKE_TOKEN = 'NO_RECAPTCHA';

export class RecaptchaEnterpriseVerifier {
  /**
   * Identifies the type of application verifier (e.g. "recaptcha-enterprise").
   */
  readonly type = RECAPTCHA_ENTERPRISE_VERIFIER_TYPE;

  private readonly auth: AuthInternal;

  /**
   *
   * @param authExtern - The corresponding Firebase {@link Auth} instance.
   *
   */
  constructor(authExtern: Auth) {
    this.auth = _castAuth(authExtern);
  }

  /**
   * Executes the verification process.
   *
   * @returns A Promise for a token that can be used to assert the validity of a request.
   */
  async verify(
    action: string = 'verify',
    forceRefresh = false
  ): Promise<string> {
    async function retrieveSiteKey(auth: AuthInternal): Promise<string> {
      if (!forceRefresh) {
        if (auth.tenantId == null && auth._agentRecaptchaConfig != null) {
          return auth._agentRecaptchaConfig.siteKey;
        }
        if (
          auth.tenantId != null &&
          auth._tenantRecaptchaConfigs[auth.tenantId] !== undefined
        ) {
          return auth._tenantRecaptchaConfigs[auth.tenantId].siteKey;
        }
      }

      return new Promise<string>(async (resolve, reject) => {
        getRecaptchaConfig(auth, {
          clientType: RecaptchaClientType.WEB,
          version: RecaptchaVersion.ENTERPRISE
        })
          .then(response => {
            if (response.recaptchaKey === undefined) {
              reject(new Error('recaptcha Enterprise site key undefined'));
            } else {
              const config = new RecaptchaConfig(response);
              if (auth.tenantId == null) {
                auth._agentRecaptchaConfig = config;
              } else {
                auth._tenantRecaptchaConfigs[auth.tenantId] = config;
              }
              return resolve(config.siteKey);
            }
          })
          .catch(error => {
            reject(error);
          });
      });
    }

    function retrieveRecaptchaToken(
      siteKey: string,
      resolve: (value: string | PromiseLike<string>) => void,
      reject: (reason?: unknown) => void
    ): void {
      const grecaptcha = window.grecaptcha;
      if (isEnterprise(grecaptcha)) {
        grecaptcha.enterprise.ready(() => {
          grecaptcha.enterprise
            .execute(siteKey, { action })
            .then(token => {
              resolve(token);
            })
            .catch(() => {
              resolve(FAKE_TOKEN);
            });
        });
      } else {
        reject(Error('No reCAPTCHA enterprise script loaded.'));
      }
    }

    return new Promise<string>((resolve, reject) => {
      retrieveSiteKey(this.auth)
        .then(siteKey => {
          if (!forceRefresh && isEnterprise(window.grecaptcha)) {
            retrieveRecaptchaToken(siteKey, resolve, reject);
          } else {
            if (typeof window === 'undefined') {
              reject(
                new Error('RecaptchaVerifier is only supported in browser')
              );
              return;
            }
            jsHelpers
              ._loadJS(RECAPTCHA_ENTERPRISE_URL + siteKey)
              .then(() => {
                retrieveRecaptchaToken(siteKey, resolve, reject);
              })
              .catch(error => {
                reject(error);
              });
          }
        })
        .catch(error => {
          reject(error);
        });
    });
  }
}

export async function injectRecaptchaFields<T>(
  auth: AuthInternal,
  request: T,
  action: RecaptchaActionName,
  captchaResp = false,
  fakeToken = false
): Promise<T> {
  const verifier = new RecaptchaEnterpriseVerifier(auth);
  let captchaResponse;
  if (fakeToken) {
    captchaResponse = FAKE_TOKEN;
  } else {
    try {
      captchaResponse = await verifier.verify(action);
    } catch (error) {
      captchaResponse = await verifier.verify(action, true);
    }
  }
  
  const newRequest = { ...request };

  if (action === RecaptchaActionName.MFA_ENROLLMENT || action === RecaptchaActionName.MFA_SIGNIN) {
    if ('phoneEnrollmentInfo' in newRequest){
      const phoneNumber = (newRequest as unknown as StartPhoneMfaEnrollmentRequest).phoneEnrollmentInfo.phoneNumber;
      const recaptchaToken = (newRequest as unknown as StartPhoneMfaEnrollmentRequest).phoneEnrollmentInfo.recaptchaToken;

      Object.assign(newRequest, {
        'phoneEnrollmentInfo': {
          phoneNumber,
          recaptchaToken,
          captchaResponse,
          'clientType': RecaptchaClientType.WEB,
          'recaptchaVersion': RecaptchaVersion.ENTERPRISE,
        },
      });
    } else
     if ('phoneSignInInfo' in newRequest) {
      const recaptchaToken = (newRequest as unknown as StartPhoneMfaSignInRequest).phoneSignInInfo.recaptchaToken;
      Object.assign(newRequest, {
        'phoneSignInInfo':{
          recaptchaToken,
          captchaResponse,
          'clientType': RecaptchaClientType.WEB,
          'recaptchaVersion': RecaptchaVersion.ENTERPRISE,
        },
      });
    }
    return newRequest;
  }

  if (!captchaResp) {
      Object.assign(newRequest, { captchaResponse });
    } else {
      Object.assign(newRequest, { 'captchaResp': captchaResponse });
    }
    Object.assign(newRequest, { 'clientType': RecaptchaClientType.WEB });
    Object.assign(newRequest, {
      'recaptchaVersion': RecaptchaVersion.ENTERPRISE
    });
  

  return newRequest;
}

type ActionMethod<TRequest, TResponse> = (
  auth: AuthInternal,
  request: TRequest
) => Promise<TResponse>;

export async function handleRecaptchaFlow<TRequest, TResponse>(
  authInstance: AuthInternal,
  request: TRequest,
  actionName: RecaptchaActionName,
  actionMethod: ActionMethod<TRequest, TResponse>,
  recaptchaProvider: RecaptchaProvider
): Promise<TResponse> {
  if (recaptchaProvider === RecaptchaProvider.EMAIL_PASSWORD_PROVIDER) {
    if (
      authInstance
        ._getRecaptchaConfig()
        ?.isProviderEnabled(RecaptchaProvider.EMAIL_PASSWORD_PROVIDER)
    ) {
      const requestWithRecaptcha = await injectRecaptchaFields(
        authInstance,
        request,
        actionName,
        actionName === RecaptchaActionName.GET_OOB_CODE
      );
      return actionMethod(authInstance, requestWithRecaptcha);
    } else {
      return actionMethod(authInstance, request).catch(async error => {
        if (error.code === `auth/${AuthErrorCode.MISSING_RECAPTCHA_TOKEN}`) {
          console.log(
            `${actionName} is protected by reCAPTCHA Enterprise for this project. Automatically triggering the reCAPTCHA flow and restarting the flow.`
          );
          const requestWithRecaptcha = await injectRecaptchaFields(
            authInstance,
            request,
            actionName,
            actionName === RecaptchaActionName.GET_OOB_CODE
          );
          return actionMethod(authInstance, requestWithRecaptcha);
        } else {
          return Promise.reject(error);
        }
      });
    }
  } else if (recaptchaProvider === RecaptchaProvider.PHONE_PROVIDER) {
    console.log('handleRecaptchaFlow - in phone if');
    if (
      authInstance
        ._getRecaptchaConfig()
        ?.isProviderEnabled(RecaptchaProvider.PHONE_PROVIDER)) {
          console.log('handleRecaptchaFlow - when phone enable');
          const requestWithRecaptcha = await injectRecaptchaFields(
            authInstance,
            request,
            actionName,
            false
          );
          console.log('handleRecaptchaFlow - returning: ', actionMethod);
          console.log('handleRecaptchaFlow - returning actionmethod with requestWithRecaptcha request: ', requestWithRecaptcha);

          return actionMethod(authInstance, requestWithRecaptcha).catch(async error => {
            // AUDIT flow
            if (
              authInstance
                ._getRecaptchaConfig()
                ?.getProviderEnforcementState(
                  RecaptchaProvider.PHONE_PROVIDER
                ) === EnforcementState.AUDIT
            ) {
              console.log('handleRecaptchaFlow - phone fails and AUDIT flow');
              if (
                error.code ===
                  `auth/${AuthErrorCode.MISSING_RECAPTCHA_TOKEN}` ||
                error.code === `auth/${AuthErrorCode.INVALID_APP_CREDENTIAL}`
              ) {
                console.log('handleRecaptchaFlow - missing recap token or invalid app cred errors');
                // fallback to recaptcha v2
                const requestWithRecaptchaV2 = await injectRecaptchaFields(
                  authInstance,
                  request,
                  actionName,
                  false,
                  true // fakeToken
                );
                console.log('handleRecaptchaFlow - returning actionmethod with recaptchav2 request: ', requestWithRecaptchaV2);
                return actionMethod(authInstance, requestWithRecaptchaV2);
                }
            }
            console.log('handleRecaptchaFlow - not AUDIT error out');
            return Promise.reject(error);
          });
      } else {
        console.log('handleRecaptchaFlow - phone not enable. Do rcv2 flow.');
        // recaptcha v2
                const requestWithRecaptchaV2 = await injectRecaptchaFields(
                  authInstance,
                  request,
                  actionName,
                  false,
                  true // fakeToken
                );
        return actionMethod(authInstance, requestWithRecaptchaV2);
      }
  }
  else {
    console.log('handleRecaptchaFlow - neither EMAIL or PHONE provider');
    return actionMethod(authInstance, request).catch(async error => {
      if (error.code === `auth/${AuthErrorCode.MISSING_RECAPTCHA_TOKEN}`) {
        console.log(
          `${actionName} is protected by reCAPTCHA Enterprise for this project. Automatically triggering the reCAPTCHA flow and restarting the flow.`
        );
        const requestWithRecaptcha = await injectRecaptchaFields(
          authInstance,
          request,
          actionName,
          false
        );
        return actionMethod(authInstance, requestWithRecaptcha);
      } else {
        return Promise.reject(error);
      }
    });
  }
}

export async function _initializeRecaptchaConfig(auth: Auth): Promise<void> {
  const authInternal = _castAuth(auth);

  const response = await getRecaptchaConfig(authInternal, {
    clientType: RecaptchaClientType.WEB,
    version: RecaptchaVersion.ENTERPRISE
  });

  const config = new RecaptchaConfig(response);
  if (authInternal.tenantId == null) {
    authInternal._agentRecaptchaConfig = config;
  } else {
    authInternal._tenantRecaptchaConfigs[authInternal.tenantId] = config;
  }

  if (config.isProviderEnabled(RecaptchaProvider.EMAIL_PASSWORD_PROVIDER ||
    config.isProviderEnabled(RecaptchaProvider.PHONE_PROVIDER))) {
    const verifier = new RecaptchaEnterpriseVerifier(authInternal);
    void verifier.verify();
  }
}
