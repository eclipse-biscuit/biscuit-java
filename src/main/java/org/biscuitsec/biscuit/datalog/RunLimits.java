package org.biscuitsec.biscuit.datalog;

import java.time.Duration;

public class RunLimits {
    private int maxFacts = 1000;
    private int maxIterations = 100;
    private Duration maxTime = Duration.ofMillis(5);

    public RunLimits() {
    }

    public RunLimits(int maxFacts, int maxIterations, Duration maxTime) {
        this.maxFacts = maxFacts;
        this.maxIterations = maxIterations;
        this.maxTime = maxTime;
    }

    public int getMaxFacts() {
        return maxFacts;
    }

    public int getMaxIterations() {
        return maxIterations;
    }

    public Duration getMaxTime() {
        return maxTime;
    }
}
