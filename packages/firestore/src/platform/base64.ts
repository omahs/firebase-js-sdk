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


/**
 * An error encountered while decoding base64 string.
 */
class Base64DecodeError extends Error {
  readonly name = 'Base64DecodeError';
}

// This file is only used under ts-node.
// eslint-disable-next-line @typescript-eslint/no-require-imports
const platform = require(`./${process.env.TEST_PLATFORM ?? 'node'}/base64`);

/** Converts a Base64 encoded string to a binary string. */
export function decodeBase64(encoded: string): string {
  const decoded = platform.decodeBase64(encoded);
  const expectedEncodedLength = 4 * Math.ceil(decoded.length / 3);

  if (encoded.length !== expectedEncodedLength) {
    throw new Base64DecodeError(
      `Invalid base64 string ` +
        `(decoded length: ${decoded.length}, ` +
        `encoded length: ${encoded.length}, ` +
        `expected encoded length: ${expectedEncodedLength})`
    );
  }
  return decoded;
}

/** Converts a binary string to a Base64 encoded string. */
export function encodeBase64(raw: string): string {
  return platform.encodeBase64(raw);
}

/**
 * True if and only if the Base64 conversion functions are available.
 * @internal
 */
export function isBase64Available(): boolean {
  return platform.isBase64Available();
}
