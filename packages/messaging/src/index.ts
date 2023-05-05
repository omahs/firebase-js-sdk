/**
 * The Firebase Cloud Messaging Web SDK.
 * This SDK does not work in Node.js.
 *
 * @packageDocumentation
 */

/**
 * @license
 * Copyright 2017 Google LLC
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

import '@firebase/installations';

import { Messaging } from './interfaces/public-types';
import { registerMessagingInWindow } from './helpers/register';

export {
  getToken,
  deleteToken,
  onMessage,
  getMessagingInWindow as getMessaging
} from './api';
export { isWindowSupported as isSupported } from './api/isSupported';
export * from './interfaces/public-types';

declare module '@firebase/component' {
  interface NameServiceMapping {
    'messaging': Messaging;
  }
}

registerMessagingInWindow();
