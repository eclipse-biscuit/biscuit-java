package org.eclipse.biscuit.datalog;

import java.time.Duration;

public final class RunLimits {
  private int maxFacts = 1000;
  private int maxIterations = 100;
  private Duration maxTime = Duration.ofMillis(5);

  public RunLimits() {}

  public RunLimits(int maxFacts, int maxIterations, Duration maxTime) {
    this.maxFacts = maxFacts;
    this.maxIterations = maxIterations;
    this.maxTime = maxTime;
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
}
