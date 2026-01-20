package org.eclipse.biscuit.regex;

public interface PatternMatcher {
  public interface Factory {
    PatternMatcher create(String regex);
  }

  boolean match(CharSequence input);
}
