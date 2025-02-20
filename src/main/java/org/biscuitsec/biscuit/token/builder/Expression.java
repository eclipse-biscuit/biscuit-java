package org.biscuitsec.biscuit.token.builder;

import org.biscuitsec.biscuit.datalog.SymbolTable;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Set;

public abstract class Expression {
    public org.biscuitsec.biscuit.datalog.expressions.Expression convert(SymbolTable symbols) {
        ArrayList<org.biscuitsec.biscuit.datalog.expressions.Op> ops = new ArrayList<>();
        this.toOpcodes(symbols, ops);

        return new org.biscuitsec.biscuit.datalog.expressions.Expression(ops);
    }

    public static Expression convertFrom(org.biscuitsec.biscuit.datalog.expressions.Expression e, SymbolTable symbols) {
        ArrayList<Op> ops = new ArrayList<>();
        Deque<Expression> stack = new ArrayDeque<Expression>(16);
        for(org.biscuitsec.biscuit.datalog.expressions.Op op: e.getOps()){
            if(op instanceof org.biscuitsec.biscuit.datalog.expressions.Op.Value) {
                org.biscuitsec.biscuit.datalog.expressions.Op.Value v = (org.biscuitsec.biscuit.datalog.expressions.Op.Value) op;
                stack.push(new Expression.Value(Term.convertFrom(v.getValue(), symbols)));
            } else if(op instanceof org.biscuitsec.biscuit.datalog.expressions.Op.Unary) {
                org.biscuitsec.biscuit.datalog.expressions.Op.Unary v = (org.biscuitsec.biscuit.datalog.expressions.Op.Unary) op;
                Expression e1 = stack.pop();

                switch (v.getOp()) {
                    case Length:
                        stack.push(new Expression.Unary(Op.Length, e1));
                        break;
                    case Negate:
                        stack.push(new Expression.Unary(Op.Negate, e1));
                        break;
                    case Parens:
                        stack.push(new Expression.Unary(Op.Parens, e1));
                        break;
                    default:
                        return null;
                }
            } else if (op instanceof org.biscuitsec.biscuit.datalog.expressions.Op.Binary) {
                org.biscuitsec.biscuit.datalog.expressions.Op.Binary v = (org.biscuitsec.biscuit.datalog.expressions.Op.Binary) op;
                Expression e2 = stack.pop();
                Expression e1 = stack.pop();

                switch (v.getOp()) {
                    case LessThan:
                        stack.push(new Expression.Binary(Op.LessThan, e1, e2));
                        break;
                    case GreaterThan:
                        stack.push(new Expression.Binary(Op.GreaterThan, e1, e2));
                        break;
                    case LessOrEqual:
                        stack.push(new Expression.Binary(Op.LessOrEqual, e1, e2));
                        break;
                    case GreaterOrEqual:
                        stack.push(new Expression.Binary(Op.GreaterOrEqual, e1, e2));
                        break;
                    case Equal:
                        stack.push(new Expression.Binary(Op.Equal, e1, e2));
                        break;
                    case NotEqual:
                        stack.push(new Expression.Binary(Op.NotEqual, e1, e2));
                        break;
                    case Contains:
                        stack.push(new Expression.Binary(Op.Contains, e1, e2));
                        break;
                    case Prefix:
                        stack.push(new Expression.Binary(Op.Prefix, e1, e2));
                        break;
                    case Suffix:
                        stack.push(new Expression.Binary(Op.Suffix, e1, e2));
                        break;
                    case Regex:
                        stack.push(new Expression.Binary(Op.Regex, e1, e2));
                        break;
                    case Add:
                        stack.push(new Expression.Binary(Op.Add, e1, e2));
                        break;
                    case Sub:
                        stack.push(new Expression.Binary(Op.Sub, e1, e2));
                        break;
                    case Mul:
                        stack.push(new Expression.Binary(Op.Mul, e1, e2));
                        break;
                    case Div:
                        stack.push(new Expression.Binary(Op.Div, e1, e2));
                        break;
                    case And:
                        stack.push(new Expression.Binary(Op.And, e1, e2));
                        break;
                    case Or:
                        stack.push(new Expression.Binary(Op.Or, e1, e2));
                        break;
                    case Intersection:
                        stack.push(new Expression.Binary(Op.Intersection, e1, e2));
                        break;
                    case Union:
                        stack.push(new Expression.Binary(Op.Union, e1, e2));
                        break;
                    case BitwiseAnd:
                        stack.push(new Expression.Binary(Op.BitwiseAnd, e1, e2));
                        break;
                    case BitwiseOr:
                        stack.push(new Expression.Binary(Op.BitwiseOr, e1, e2));
                        break;
                    case BitwiseXor:
                        stack.push(new Expression.Binary(Op.BitwiseXor, e1, e2));
                        break;
                    default:
                        return null;
                }
            }
        }

        return stack.pop();
    }

    public abstract void toOpcodes(SymbolTable symbols, List<org.biscuitsec.biscuit.datalog.expressions.Op> ops);
    public abstract void gatherVariables(Set<String> variables);

    public enum Op {
        Negate,
        Parens,
        LessThan,
        GreaterThan,
        LessOrEqual,
        GreaterOrEqual,
        Equal,
        NotEqual,
        Contains,
        Prefix,
        Suffix,
        Regex,
        Add,
        Sub,
        Mul,
        Div,
        And,
        Or,
        Length,
        Intersection,
        Union,
        BitwiseAnd,
        BitwiseOr,
        BitwiseXor
    }

    public final static class Value extends Expression {
        public final Term value;

        public Value(Term value) {
            this.value = value;
        }

        public void toOpcodes(SymbolTable symbols, List<org.biscuitsec.biscuit.datalog.expressions.Op> ops) {
            ops.add(new org.biscuitsec.biscuit.datalog.expressions.Op.Value(this.value.convert(symbols)));
        }

        public  void gatherVariables(Set<String> variables) {
            if(this.value instanceof Term.Variable) {
                variables.add(((Term.Variable) this.value).value);
            }
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            Value value1 = (Value) o;

            return value != null ? value.equals(value1.value) : value1.value == null;
        }

        @Override
        public int hashCode() {
            return value != null ? value.hashCode() : 0;
        }

        @Override
        public String toString() {
            return value.toString();
        }
    }

    public final static class Unary extends Expression {
        private final Op op;
        private final Expression arg1;

        public Unary(Op op, Expression arg1) {
            this.op = op;
            this.arg1 = arg1;
        }

        public void toOpcodes(SymbolTable symbols, List<org.biscuitsec.biscuit.datalog.expressions.Op> ops) {
            this.arg1.toOpcodes(symbols, ops);

            switch (this.op) {
                case Negate:
                    ops.add(new org.biscuitsec.biscuit.datalog.expressions.Op.Unary(org.biscuitsec.biscuit.datalog.expressions.Op.UnaryOp.Negate));
                    break;
                case Parens:
                    ops.add(new org.biscuitsec.biscuit.datalog.expressions.Op.Unary(org.biscuitsec.biscuit.datalog.expressions.Op.UnaryOp.Parens));
                    break;
                case Length:
                    ops.add(new org.biscuitsec.biscuit.datalog.expressions.Op.Unary(org.biscuitsec.biscuit.datalog.expressions.Op.UnaryOp.Length));
                    break;
            }
        }

        public  void gatherVariables(Set<String> variables) {
            this.arg1.gatherVariables(variables);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            Unary unary = (Unary) o;

            if (op != unary.op) return false;
            return arg1.equals(unary.arg1);
        }

        @Override
        public int hashCode() {
            int result = op.hashCode();
            result = 31 * result + arg1.hashCode();
            return result;
        }

        @Override
        public String toString() {
            switch(op) {
                case Negate:
                    return "!"+arg1;
                case Parens:
                    return "("+arg1+")";
                case Length:
                    return arg1.toString()+".length()";
            }
            return "";
        }
    }

    public final static class Binary extends Expression {
        private final Op op;
        private final Expression arg1;
        private final Expression arg2;

        public Binary(Op op, Expression arg1, Expression arg2) {
            this.op = op;
            this.arg1 = arg1;
            this.arg2 = arg2;
        }

        public void toOpcodes(SymbolTable symbols, List<org.biscuitsec.biscuit.datalog.expressions.Op> ops) {
            this.arg1.toOpcodes(symbols, ops);
            this.arg2.toOpcodes(symbols, ops);

            switch (this.op) {
                case LessThan:
                    ops.add(new org.biscuitsec.biscuit.datalog.expressions.Op.Binary(org.biscuitsec.biscuit.datalog.expressions.Op.BinaryOp.LessThan));
                    break;
                case GreaterThan:
                    ops.add(new org.biscuitsec.biscuit.datalog.expressions.Op.Binary(org.biscuitsec.biscuit.datalog.expressions.Op.BinaryOp.GreaterThan));
                    break;
                case LessOrEqual:
                    ops.add(new org.biscuitsec.biscuit.datalog.expressions.Op.Binary(org.biscuitsec.biscuit.datalog.expressions.Op.BinaryOp.LessOrEqual));
                    break;
                case GreaterOrEqual:
                    ops.add(new org.biscuitsec.biscuit.datalog.expressions.Op.Binary(org.biscuitsec.biscuit.datalog.expressions.Op.BinaryOp.GreaterOrEqual));
                    break;
                case Equal:
                    ops.add(new org.biscuitsec.biscuit.datalog.expressions.Op.Binary(org.biscuitsec.biscuit.datalog.expressions.Op.BinaryOp.Equal));
                    break;
                case NotEqual:
                    ops.add(new org.biscuitsec.biscuit.datalog.expressions.Op.Binary(org.biscuitsec.biscuit.datalog.expressions.Op.BinaryOp.NotEqual));
                    break;
                case Contains:
                    ops.add(new org.biscuitsec.biscuit.datalog.expressions.Op.Binary(org.biscuitsec.biscuit.datalog.expressions.Op.BinaryOp.Contains));
                    break;
                case Prefix:
                    ops.add(new org.biscuitsec.biscuit.datalog.expressions.Op.Binary(org.biscuitsec.biscuit.datalog.expressions.Op.BinaryOp.Prefix));
                    break;
                case Suffix:
                    ops.add(new org.biscuitsec.biscuit.datalog.expressions.Op.Binary(org.biscuitsec.biscuit.datalog.expressions.Op.BinaryOp.Suffix));
                    break;
                case Regex:
                    ops.add(new org.biscuitsec.biscuit.datalog.expressions.Op.Binary(org.biscuitsec.biscuit.datalog.expressions.Op.BinaryOp.Regex));
                    break;
                case Add:
                    ops.add(new org.biscuitsec.biscuit.datalog.expressions.Op.Binary(org.biscuitsec.biscuit.datalog.expressions.Op.BinaryOp.Add));
                    break;
                case Sub:
                    ops.add(new org.biscuitsec.biscuit.datalog.expressions.Op.Binary(org.biscuitsec.biscuit.datalog.expressions.Op.BinaryOp.Sub));
                    break;
                case Mul:
                    ops.add(new org.biscuitsec.biscuit.datalog.expressions.Op.Binary(org.biscuitsec.biscuit.datalog.expressions.Op.BinaryOp.Mul));
                    break;
                case Div:
                    ops.add(new org.biscuitsec.biscuit.datalog.expressions.Op.Binary(org.biscuitsec.biscuit.datalog.expressions.Op.BinaryOp.Div));
                    break;
                case And:
                    ops.add(new org.biscuitsec.biscuit.datalog.expressions.Op.Binary(org.biscuitsec.biscuit.datalog.expressions.Op.BinaryOp.And));
                    break;
                case Or:
                    ops.add(new org.biscuitsec.biscuit.datalog.expressions.Op.Binary(org.biscuitsec.biscuit.datalog.expressions.Op.BinaryOp.Or));
                    break;
                case Intersection:
                    ops.add(new org.biscuitsec.biscuit.datalog.expressions.Op.Binary(org.biscuitsec.biscuit.datalog.expressions.Op.BinaryOp.Intersection));
                    break;
                case Union:
                    ops.add(new org.biscuitsec.biscuit.datalog.expressions.Op.Binary(org.biscuitsec.biscuit.datalog.expressions.Op.BinaryOp.Union));
                    break;
                case BitwiseAnd:
                    ops.add(new org.biscuitsec.biscuit.datalog.expressions.Op.Binary(org.biscuitsec.biscuit.datalog.expressions.Op.BinaryOp.BitwiseAnd));
                    break;
                case BitwiseOr:
                    ops.add(new org.biscuitsec.biscuit.datalog.expressions.Op.Binary(org.biscuitsec.biscuit.datalog.expressions.Op.BinaryOp.BitwiseOr));
                    break;
                case BitwiseXor:
                    ops.add(new org.biscuitsec.biscuit.datalog.expressions.Op.Binary(org.biscuitsec.biscuit.datalog.expressions.Op.BinaryOp.BitwiseXor));
                    break;
            }
        }

        public  void gatherVariables(Set<String> variables) {
            this.arg1.gatherVariables(variables);
            this.arg2.gatherVariables(variables);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            Binary binary = (Binary) o;

            if (op != binary.op) return false;
            if (!arg1.equals(binary.arg1)) return false;
            return arg2.equals(binary.arg2);
        }

        @Override
        public int hashCode() {
            int result = op.hashCode();
            result = 31 * result + arg1.hashCode();
            result = 31 * result + arg2.hashCode();
            return result;
        }

        @Override
        public String toString() {
            switch(op) {
                case LessThan:
                    return arg1.toString() + " < " + arg2.toString();
                case GreaterThan:
                    return arg1.toString() + " > " + arg2.toString();
                case LessOrEqual:
                    return arg1.toString() + " <= " + arg2.toString();
                case GreaterOrEqual:
                    return arg1.toString() + " >= " + arg2.toString();
                case Equal:
                    return arg1.toString() + " == " + arg2.toString();
                case NotEqual:
                    return arg1.toString() + " != " + arg2.toString();
                case Contains:
                    return arg1.toString() + ".contains(" + arg2.toString()+")";
                case Prefix:
                    return arg1.toString() + ".starts_with(" + arg2.toString()+")";
                case Suffix:
                    return arg1.toString() + ".ends_with(" + arg2.toString()+")";
                case Regex:
                    return arg1.toString() + ".matches(" + arg2.toString()+")";
                case Add:
                    return arg1.toString() + " + " + arg2.toString();
                case Sub:
                    return arg1.toString() + " - " + arg2.toString();
                case Mul:
                    return arg1.toString() + " * " + arg2.toString();
                case Div:
                    return arg1.toString() + " / " + arg2.toString();
                case And:
                    return arg1.toString() + " && " + arg2.toString();
                case Or:
                    return arg1.toString() + " || " + arg2.toString();
                case Intersection:
                    return arg1.toString() + ".intersection(" + arg2.toString()+")";
                case Union:
                    return arg1.toString() + ".union(" + arg2.toString()+")";
                case BitwiseAnd:
                    return arg1.toString() + " & " + arg2.toString();
                case BitwiseOr:
                    return arg1.toString() + " | " + arg2.toString();
                case BitwiseXor:
                    return arg1.toString() + " ^ " + arg2.toString();
            }
            return "";
        }
    }
}
