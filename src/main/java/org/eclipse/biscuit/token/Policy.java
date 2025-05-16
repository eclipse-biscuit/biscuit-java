package org.eclipse.biscuit.token;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import org.eclipse.biscuit.token.builder.Rule;

public final class Policy {
  public List<Rule> queries() {
    return queries;
  }

  public Kind kind() {
    return kind;
  }

  public enum Kind {
    ALLOW,
    DENY,
  }

  private final List<Rule> queries;
  private Kind kind;

  public Policy(List<Rule> queries, Kind kind) {
    this.queries = queries;
    this.kind = kind;
  }

  public Policy(Rule query, Kind kind) {
    ArrayList<Rule> r = new ArrayList<>();
    r.add(query);

    this.queries = r;
    this.kind = kind;
  }

  @Override
  public String toString() {
    final List<String> qs =
        queries.stream().map((q) -> q.bodyToString()).collect(Collectors.toList());

    switch (this.kind) {
      case ALLOW:
        return "allow if " + String.join(" or ", qs);
      case DENY:
        return "deny if " + String.join(" or ", qs);
      default:
        return null;
    }
  }
}
