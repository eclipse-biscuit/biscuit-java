package org.eclipse.biscuit.regex;

import java.util.ServiceLoader;
import java.util.stream.Collectors;

public abstract class PatternMatcher {
  public interface Factory {
    PatternMatcher create(String regex);
  }

  private static final Factory factory;

  static {
    var factories =
        ServiceLoader.load(PatternMatcher.Factory.class).stream().collect(Collectors.toList());
    if (factories.size() != 1) {
      throw new IllegalStateException(
          "A single PatternMatcher implementation expected; found " + factories.size());
    }
    factory = factories.get(0).get();
  }

  public static PatternMatcher create(String regex) {
    return factory.create(regex);
  }

  public abstract boolean match(CharSequence input);
}
