/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.crypto;

import io.vavr.control.Option;

/**
 * Used to find the key associated with a key id
 *
 * <p>When the root key is changed, it might happen that multiple root keys are in use at the same
 * time. Tokens can carry a root key id, that can be used to indicate which key will verify it.
 */
public interface KeyDelegate {
  Option<PublicKey> getRootKey(Option<Integer> keyId);
}
