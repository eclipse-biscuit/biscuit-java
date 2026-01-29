package org.eclipse.biscuit.regex;

import com.google.re2j.Pattern;

public final class DefaultPatternMatcherFactory implements PatternMatcher.Factory {
  @Override
  public PatternMatcher create(String regex) {
    var p = Pattern.compile(regex);
    return new PatternMatcher() {
      @Override
      public boolean match(CharSequence input) {
        return p.matcher(input).find();
      }
    };
  }
}
