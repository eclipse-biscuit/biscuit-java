package org.eclipse.biscuit.datalog;

public class StepCounter implements Cloneable {
  private int counter;
  private final int maxSteps;

  public StepCounter(int maxSteps) {
    this.maxSteps = maxSteps;
    this.counter = 0;
  }

  public boolean step() {
    return ++counter <= maxSteps;
  }

  public boolean exceeded() {
    return counter > maxSteps;
  }

  @Override
  public StepCounter clone() {
    try {
      return (StepCounter) super.clone();
    } catch (CloneNotSupportedException e) {
      throw new AssertionError();
    }
  }
}
