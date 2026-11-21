package org.eclipse.biscuit.datalog;

import org.eclipse.biscuit.error.Error;

public final class StepBudget {
  private final StepCounter counter;
  private final long maxSteps;

  StepBudget(StepCounter counter, long maxSteps) {
    this.counter = counter;
    this.maxSteps = maxSteps;
  }

  public void step() throws Error.TooManySteps {
    if (++counter.count > maxSteps) {
      throw new Error.TooManySteps();
    }
  }
}
