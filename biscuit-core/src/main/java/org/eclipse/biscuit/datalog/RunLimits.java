/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 *  SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.biscuit.datalog;

import java.time.Duration;

public final class RunLimits {
  private int maxFacts = 1000;
  private int maxIterations = 100;
  private Duration maxTime = Duration.ofMillis(5);
  private long maxSteps = 1000;

  public RunLimits() {}

  public RunLimits(int maxFacts, int maxIterations, Duration maxTime) {
    this(maxFacts, maxIterations, maxTime, 1000);
  }

  public RunLimits(int maxFacts, int maxIterations, Duration maxTime, long maxSteps) {
    this.maxFacts = maxFacts;
    this.maxIterations = maxIterations;
    this.maxTime = maxTime;
    this.maxSteps = maxSteps;
  }

  public int getMaxFacts() {
    return this.maxFacts;
  }

  public int getMaxIterations() {
    return this.maxIterations;
  }

  public Duration getMaxTime() {
    return this.maxTime;
  }

  public long getMaxSteps() {
    return this.maxSteps;
  }
}
