package org.eclipse.biscuit.datalog;

public final class StepBudget {
  private final StepCounter counter;
  private final long maxSteps;

  StepBudget(StepCounter counter, long maxSteps) {
    this.counter = counter;
    this.maxSteps = maxSteps;
  }

  public boolean step() {
    return ++counter.count <= maxSteps;
  }

  public boolean exceeded() {
    return counter.count > maxSteps;
  }
}
