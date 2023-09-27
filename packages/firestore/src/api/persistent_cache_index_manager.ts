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

import {
  firestoreClientDeleteAllFieldIndexes,
  firestoreClientSetPersistentCacheIndexAutoCreationEnabled,
  FirestoreClient
} from '../core/firestore_client';
import { cast } from '../util/input_validation';
import { logDebug, logWarn } from '../util/log';

import { ensureFirestoreConfigured, Firestore } from './database';

/**
 * A `PersistentCacheIndexManager` for configuring persistent cache indexes used
 * for local query execution.
 *
 * To use, call `getPersistentCacheIndexManager()` to get an instance.
 */
export class PersistentCacheIndexManager {
  /** A type string to uniquely identify instances of this class. */
  readonly type: 'PersistentCacheIndexManager' = 'PersistentCacheIndexManager';

  /** @hideconstructor */
  constructor(readonly _client: FirestoreClient) {}
}

/**
 * Returns the PersistentCache Index Manager used by the given `Firestore`
 * object.
 *
 * @return The `PersistentCacheIndexManager` instance, or `null` if local
 * persistent storage is not in use.
 */
export function getPersistentCacheIndexManager(
  firestore: Firestore
): PersistentCacheIndexManager | null {
  firestore = cast(firestore, Firestore);

  const cachedInstance = persistentCacheIndexManagerByFirestore.get(firestore);
  if (cachedInstance) {
    return cachedInstance;
  }

  const client = ensureFirestoreConfigured(firestore);
  if (client._uninitializedComponentsProvider?._offlineKind !== 'persistent') {
    return null;
  }

  const instance = new PersistentCacheIndexManager(client);
  persistentCacheIndexManagerByFirestore.set(firestore, instance);
  return instance;
}

/**
 * Enables the SDK to create persistent cache indexes automatically for local
 * query execution when the SDK believes cache indexes can help improve
 * performance.
 *
 * This feature is disabled by default.
 */
export function enablePersistentCacheIndexAutoCreation(
  indexManager: PersistentCacheIndexManager
): void {
  setPersistentCacheIndexAutoCreationEnabled(indexManager, true);
}

/**
 * Stops creating persistent cache indexes automatically for local query
 * execution. The indexes which have been created by calling
 * `enablePersistentCacheIndexAutoCreation()` still take effect.
 */
export function disablePersistentCacheIndexAutoCreation(
  indexManager: PersistentCacheIndexManager
): void {
  setPersistentCacheIndexAutoCreationEnabled(indexManager, false);
}

/**
 * Removes all persistent cache indexes.
 *
 * Please note this function will also deletes indexes generated by
 * `setIndexConfiguration()`, which is deprecated.
 */
export function deleteAllPersistentCacheIndexes(
  indexManager: PersistentCacheIndexManager
): void {
  indexManager._client.verifyNotTerminated();

  const promise = firestoreClientDeleteAllFieldIndexes(indexManager._client);

  promise
    .then(_ => logDebug('deleting all persistent cache indexes succeeded'))
    .catch(error =>
      logWarn('deleting all persistent cache indexes failed', error)
    );
}

function setPersistentCacheIndexAutoCreationEnabled(
  indexManager: PersistentCacheIndexManager,
  isEnabled: boolean
): void {
  indexManager._client.verifyNotTerminated();

  const promise = firestoreClientSetPersistentCacheIndexAutoCreationEnabled(
    indexManager._client,
    isEnabled
  );

  promise
    .then(_ =>
      logDebug(
        `setting persistent cache index auto creation ` +
          `isEnabled=${isEnabled} succeeded`
      )
    )
    .catch(error =>
      logWarn(
        `setting persistent cache index auto creation ` +
          `isEnabled=${isEnabled} failed`,
        error
      )
    );
}

/**
 * Maps `Firestore` instances to their corresponding
 * `PersistentCacheIndexManager` instances.
 *
 * Use a `WeakMap` so that the mapping will be automatically dropped when the
 * `Firestore` instance is garbage collected. This emulates a private member
 * as described in https://goo.gle/454yvug.
 */
const persistentCacheIndexManagerByFirestore = new WeakMap<
  Firestore,
  PersistentCacheIndexManager
>();
