/**
 * Tests for the safe arithmetic evaluator that replaced eval().
 * Confirms it computes valid arithmetic AND rejects injection /
 * malformed input instead of executing it.
 */
import {safeEvaluate} from '../src/utils/safeEvaluate';

describe('safeEvaluate', () => {
  it('evaluates basic arithmetic with correct precedence', () => {
    expect(safeEvaluate('2+3*4')).toBe(14);
    expect(safeEvaluate('(1+2)/3')).toBe(1);
    expect(safeEvaluate('6*7')).toBe(42);
    expect(safeEvaluate('10 - 2 - 3')).toBe(5);
  });

  it('supports decimals and unary minus', () => {
    expect(safeEvaluate('1.5 + 2.5')).toBe(4);
    expect(safeEvaluate('-5 + 3')).toBe(-2);
    expect(safeEvaluate('3 * -2')).toBe(-6);
  });

  it('rejects code-injection payloads instead of executing them', () => {
    expect(() => safeEvaluate("require('fs')")).toThrow();
    expect(() => safeEvaluate('process.exit(1)')).toThrow();
    expect(() => safeEvaluate("global.foo='bar'")).toThrow();
    expect(() => safeEvaluate("alert('x')")).toThrow();
    expect(() => safeEvaluate('1;while(true){}')).toThrow();
  });

  it('rejects empty and malformed expressions', () => {
    expect(() => safeEvaluate('')).toThrow();
    expect(() => safeEvaluate('   ')).toThrow();
    expect(() => safeEvaluate('2+')).toThrow();
    expect(() => safeEvaluate('(1+2')).toThrow();
    expect(() => safeEvaluate('1/0')).toThrow();
  });

  it('rejects chained unary operators', () => {
    expect(() => safeEvaluate('2+++2')).toThrow();
    expect(() => safeEvaluate('2---2')).toThrow();
    expect(() => safeEvaluate('--5')).toThrow();
    // A single unary after a binary op / start is still valid.
    expect(safeEvaluate('3 * -2')).toBe(-6);
    expect(safeEvaluate('-5 + 3')).toBe(-2);
  });
});
