package org.eclipse.biscuit.datalog;

public final class StepCounter {
  long count;

  public StepCounter() {
    this(0);
  }

  public StepCounter(long taken) {
    this.count = taken;
  }

  public long taken() {
    return this.count;
  }

  public StepBudget budget(long maxSteps) {
    return new StepBudget(this, maxSteps);
  }
}
