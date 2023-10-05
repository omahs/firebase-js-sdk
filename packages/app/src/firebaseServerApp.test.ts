/**
 * @license
 * Copyright 2023 Google LLC
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

import { expect } from 'chai';
import '../test/setup';
import { FirebaseAppImpl } from './firebaseApp';
import { FirebaseServerAppImpl } from './firebaseServerApp';
import { ComponentContainer } from '@firebase/component';


const setCookieCb = (name: string, value: string|undefined, options: object ) : void => { 
  return;
}

const getCookieCb = (name: string) : string|undefined =>  { 
  return;
}

const getHeaderCb = (name: string) : string|undefined => { 
  return;
}

describe('FirebaseServerApp', () => {
  it('has various accessors', () => {
    const options = {
      apiKey: 'APIKEY'
    };

    const serverAppSettings = {
      name: "test",
      automaticDataCollectionEnabled: false,
      setCookie: setCookieCb,
      getCookie: getCookieCb,
      getHeader: getHeaderCb,
      deleteOnDeref: options,
    };

    const firebaseServerAppImpl = new FirebaseServerAppImpl(
      options,
      serverAppSettings,
      new ComponentContainer('test')
    );
    
    expect(firebaseServerAppImpl.automaticDataCollectionEnabled).to.be.false;
    expect(firebaseServerAppImpl.name).to.equal('test');
    expect(firebaseServerAppImpl.options).to.deep.equal(options);
  });

  it('deep-copies options', () => {
    const options = {
      apiKey: 'APIKEY'
    };

    const serverAppSettings = {
      name: "test",
      automaticDataCollectionEnabled: false,
      setCookie: setCookieCb,
      getCookie: getCookieCb,
      getHeader: getHeaderCb,
      deleteOnDeref: options,
    };

    const firebaseServerAppImpl = new FirebaseServerAppImpl(
      options,
      serverAppSettings,
      new ComponentContainer('test')
    );

    expect(firebaseServerAppImpl.options).to.not.equal(options);
    expect(firebaseServerAppImpl.options).to.deep.equal(options);
  });

  it('sets automaticDataCollectionEnabled', () => {
    const options = {
      apiKey: 'APIKEY'
    };

    const serverAppSettings = {
      name: "test",
      automaticDataCollectionEnabled: false,
      setCookie: setCookieCb,
      getCookie: getCookieCb,
      getHeader: getHeaderCb,
      deleteOnDeref: options,
    };

    const firebaseServerAppImpl = new FirebaseServerAppImpl(
      options,
      serverAppSettings,
      new ComponentContainer('test')
    );

    expect(firebaseServerAppImpl.automaticDataCollectionEnabled).to.be.false;
    firebaseServerAppImpl.automaticDataCollectionEnabled = true;
    expect(firebaseServerAppImpl.automaticDataCollectionEnabled).to.be.true;
  });

  it('throws accessing any property after being deleted', () => {
    const options = {
      apiKey: 'APIKEY'
    };

    const serverAppSettings = {
      name: "test",
      automaticDataCollectionEnabled: false,
      setCookie: setCookieCb,
      getCookie: getCookieCb,
      getHeader: getHeaderCb,
      deleteOnDeref: options,
    };

    const firebaseServerAppImpl = new FirebaseServerAppImpl(
      options,
      serverAppSettings,
      new ComponentContainer('test')
    );

    expect(() => firebaseServerAppImpl.name).to.not.throw();
    (firebaseServerAppImpl as unknown as FirebaseServerAppImpl).isDeleted = true;

    expect(() => {
      firebaseServerAppImpl.name;
    }).throws("Firebase App named 'test' already deleted");
    expect(() => firebaseServerAppImpl.options).throws(
      "Firebase App named 'test' already deleted"
    );
    expect(() => firebaseServerAppImpl.automaticDataCollectionEnabled).throws(
      "Firebase App named 'test' already deleted"
    );
  });
});
