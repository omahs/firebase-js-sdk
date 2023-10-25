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

import { expect, use } from 'chai';
import chaiAsPromised from 'chai-as-promised';
import * as sinon from 'sinon';
import sinonChai from 'sinon-chai';

import { Endpoint, RecaptchaClientType, RecaptchaVersion, RecaptchaActionName } from '../../api';
import { mockEndpointWithParams } from '../../../test/helpers/api/helper';
import { testAuth, TestAuth } from '../../../test/helpers/mock_auth';
import * as mockFetch from '../../../test/helpers/mock_fetch';
import { ServerError } from '../../api/errors';

import { MockGreCAPTCHATopLevel } from './recaptcha_mock';
import {
  RecaptchaEnterpriseVerifier,
  FAKE_TOKEN, 
  injectRecaptchaFields
} from './recaptcha_enterprise_verifier';

use(chaiAsPromised);
use(sinonChai);

describe('platform_browser/recaptcha/recaptcha_enterprise_verifier', () => {
  let auth: TestAuth;
  let verifier: RecaptchaEnterpriseVerifier;
  const recaptchaConfigResponseEnforce = {
    recaptchaKey: 'foo/bar/to/site-key',
    recaptchaEnforcementState: [
      {
        provider: 'EMAIL_PASSWORD_PROVIDER',
        enforcementState: 'ENFORCE'
      },
      {
        provider: 'PHONE_PROVIDER',
        enforcementState: 'ENFORCE'
      }
    ]
  };

  const getRecaptchaConfigRequest = {
    clientType: RecaptchaClientType.WEB,
    version: RecaptchaVersion.ENTERPRISE
  };

  let recaptcha: MockGreCAPTCHATopLevel;

  beforeEach(async () => {
    auth = await testAuth();
    mockFetch.setUp();
    verifier = new RecaptchaEnterpriseVerifier(auth);
    recaptcha = new MockGreCAPTCHATopLevel();
    window.grecaptcha = recaptcha;
  });

  afterEach(() => {
    mockFetch.tearDown();
    sinon.restore();
  });

  context('#verify', () => {
    it('returns if response is available', async () => {
      mockEndpointWithParams(
        Endpoint.GET_RECAPTCHA_CONFIG,
        getRecaptchaConfigRequest,
        recaptchaConfigResponseEnforce
      );
      sinon
        .stub(recaptcha.enterprise, 'execute')
        .returns(Promise.resolve('recaptcha-response'));
      expect(await verifier.verify()).to.eq('recaptcha-response');
    });

    it('reject if error is thrown when retrieve site key', async () => {
      mockEndpointWithParams(
        Endpoint.GET_RECAPTCHA_CONFIG,
        getRecaptchaConfigRequest,
        {
          error: {
            code: 400,
            message: ServerError.MISSING_CLIENT_TYPE
          }
        },
        400
      );
      sinon
        .stub(recaptcha.enterprise, 'execute')
        .returns(Promise.resolve('recaptcha-response'));
      await expect(verifier.verify()).to.be.rejectedWith(
        Error,
        'auth/missing-client-type'
      );
    });

    it('return fake recaptcha token if error is thrown when retrieve recaptcha token', async () => {
      mockEndpointWithParams(
        Endpoint.GET_RECAPTCHA_CONFIG,
        getRecaptchaConfigRequest,
        recaptchaConfigResponseEnforce
      );
      sinon
        .stub(recaptcha.enterprise, 'execute')
        .returns(Promise.reject(Error('retrieve-recaptcha-token-error')));
      expect(await verifier.verify()).to.eq(FAKE_TOKEN);
    });
  });

  context('#injectRecaptchaFields', () => {
    it('injects recaptcha enterprise fields to SignInWithPassword request', async () => {
      mockEndpointWithParams(
        Endpoint.GET_RECAPTCHA_CONFIG,
        getRecaptchaConfigRequest,
        recaptchaConfigResponseEnforce
      );
      sinon
        .stub(recaptcha.enterprise, 'execute')
        .returns(Promise.resolve('recaptcha-response'));

      const request = {
        returnSecureToken: true,
        email: 'email',
        password: 'password',
        clientType: RecaptchaClientType.WEB
      };
      const requestWithRecaptcha = await injectRecaptchaFields(
        auth,
        request,
        RecaptchaActionName.SIGN_IN_WITH_PASSWORD,
        false
      );
      const expectedRequest = {
        returnSecureToken: true,
        email: 'email',
        password: 'password',
        clientType: RecaptchaClientType.WEB,
        captchaResponse: 'recaptcha-response',
        recaptchaVersion: RecaptchaVersion.ENTERPRISE
      };

      expect(requestWithRecaptcha).to.eql(expectedRequest);
    });

    it('injects recaptcha enterprise fields when captchaResp is true', async () => {
      mockEndpointWithParams(
        Endpoint.GET_RECAPTCHA_CONFIG,
        getRecaptchaConfigRequest,
        recaptchaConfigResponseEnforce
      );
      sinon
        .stub(recaptcha.enterprise, 'execute')
        .returns(Promise.resolve('recaptcha-response'));

      const request = {
        requestType: 'requestType',
        email: 'email',
        clientType: RecaptchaClientType.WEB
      };
      const requestWithRecaptcha = await injectRecaptchaFields(
        auth,
        request,
        RecaptchaActionName.GET_OOB_CODE,
        true
      );
      const expectedRequest = {
        requestType: 'requestType',
        email: 'email',
        clientType: RecaptchaClientType.WEB,
        captchaResp: 'recaptcha-response',
        recaptchaVersion: RecaptchaVersion.ENTERPRISE
      };

      expect(requestWithRecaptcha).to.eql(expectedRequest);
    });

    it('injects recaptcha enterprise fields to StartPhoneMfaEnrollment request', async () => {
      mockEndpointWithParams(
        Endpoint.GET_RECAPTCHA_CONFIG,
        getRecaptchaConfigRequest,
        recaptchaConfigResponseEnforce
      );
      sinon
        .stub(recaptcha.enterprise, 'execute')
        .returns(Promise.resolve('recaptcha-response'));

      const request = {
        idToken: 'idToken',
          phoneEnrollmentInfo: {
            phoneNumber: '123456',
            recaptchaToken: 'recaptchaToken'
          }
      }
      const requestWithRecaptcha = await injectRecaptchaFields(
        auth,
        request,
        RecaptchaActionName.MFA_ENROLLMENT,
        false
      );
      const expectedRequest =  {
        idToken: 'idToken',
          phoneEnrollmentInfo: {
            phoneNumber: '123456',
            recaptchaToken: 'recaptchaToken',
            captchaResponse: 'recaptcha-response',
          clientType: RecaptchaClientType.WEB,
          recaptchaVersion: RecaptchaVersion.ENTERPRISE
          }
      }

      expect(requestWithRecaptcha).to.eql(expectedRequest);
    });

    it('injects recaptcha enterprise fields to StartPhoneMfaSignInRequest request', async () => {
      mockEndpointWithParams(
        Endpoint.GET_RECAPTCHA_CONFIG,
        getRecaptchaConfigRequest,
        recaptchaConfigResponseEnforce
      );
      sinon
        .stub(recaptcha.enterprise, 'execute')
        .returns(Promise.resolve('recaptcha-response'));

      const request = {
        mfaPendingCredential: 'mfaPendingCredential',
        mfaEnrollmentId: 'mfaEnrollmentId',
        phoneSignInInfo: {
          recaptchaToken: 'recaptchaToken'
        }}
      const requestWithRecaptcha = await injectRecaptchaFields(
        auth,
        request,
        RecaptchaActionName.MFA_SIGNIN,
        false
      );
      const expectedRequest =  {
        mfaPendingCredential: 'mfaPendingCredential',
        mfaEnrollmentId: 'mfaEnrollmentId',
        phoneSignInInfo: {
          recaptchaToken: 'recaptchaToken',
          captchaResponse: 'recaptcha-response',
          clientType: RecaptchaClientType.WEB,
          recaptchaVersion: RecaptchaVersion.ENTERPRISE
        }}

      expect(requestWithRecaptcha).to.eql(expectedRequest);
    });
  });
});
