package org.biscuitsec.biscuit.token.builder;

import org.biscuitsec.biscuit.error.Error;

import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;

import static org.biscuitsec.biscuit.datalog.Check.Kind.One;

public class Utils {
    public static Fact fact(String name, List<Term> ids) throws Error.Language {
        return new Fact(name, ids);
    }

    public static Predicate pred(String name, List<Term> ids) {
        return new Predicate(name, ids);
    }

    public static Rule rule(String headName, List<Term> headIds,
                            List<Predicate> predicates) {
        return new Rule(pred(headName, headIds), predicates, new ArrayList<>(), new ArrayList<>());
    }

    public static Rule constrained_rule(String headName, List<Term> headIds,
                                        List<Predicate> predicates,
                                        List<Expression> expressions) {
        return new Rule(pred(headName, headIds), predicates, expressions, new ArrayList<>());
    }

    public static Check check(Rule rule) {
        return new Check(One,rule);
    }

    public static Term integer(long i) {
        return new Term.Integer(i);
    }

    public static Term string(String s) {
        return new Term.Str(s);
    }

    public static Term s(String str) {
        return new Term.Str(str);
    }

    public static Term date(Date d) {
        return new Term.Date(d.getTime() / 1000);
    }

    public static Term var(String name) {
        return new Term.Variable(name);
    }

    public static Term set(HashSet<Term> s) {
        return new Term.Set(s);
    }

    public static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
    public static String byteArrayToHexString(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

    public static byte[] hexStringToByteArray(String hex) {
        hex = hex.toUpperCase();
        int l = hex.length();
        byte[] data = new byte[l/2];
        for (int i = 0; i < l; i += 2) {
            data[i/2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i+1), 16));
        }
        return data;
    }
}
