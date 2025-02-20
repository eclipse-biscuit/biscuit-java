package org.biscuitsec.biscuit.datalog;

import io.vavr.Tuple2;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

public class RuleSet {
    public final HashMap<TrustedOrigins, List<Tuple2<Long, Rule>>> rules;

    public RuleSet() {
        rules = new HashMap<>();
    }

    public void add(Long origin, TrustedOrigins scope, Rule rule) {
        if (!rules.containsKey(scope)) {
            rules.put(scope, List.of(new Tuple2<>(origin, rule)));
        } else {
            rules.get(scope).add(new Tuple2<>(origin, rule));
        }
    }

    public RuleSet clone() {
        RuleSet newRules = new RuleSet();

        for (Map.Entry<TrustedOrigins, List<Tuple2<Long, Rule>>> entry : this.rules.entrySet()) {
            List<Tuple2<Long, Rule>> l = new ArrayList<>(entry.getValue());
            newRules.rules.put(entry.getKey(), l);
        }

        return newRules;
    }

    public Stream<Rule> stream() {
        return rules.entrySet()
                .stream()
                .flatMap(entry -> entry.getValue()
                        .stream()
                        .map(t -> t._2));
    }

    public void clear() {
        rules.clear();
    }
}
