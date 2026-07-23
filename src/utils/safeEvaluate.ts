/*
 * SECURITY FIX (Code Injection + Insufficient Input Validation)
 * 
 * The original app evaluated user-entered note text with eval(),
 * which executes ARBITRARY JavaScript (CWE-95). A malicious note
 * such as `require('fs')...` or `while(true){}` would run with the
 * app's privileges.
 *
 * This module replaces eval() with a self-contained arithmetic
 * evaluator that:
 *   1. Rejects any character outside a strict whitelist
 *      ( digits 0-9, . + - * / ( ) and spaces ).
 *   2. Tokenizes the input, then evaluates it with the
 *      shunting-yard algorithm on a numeric stack.
 * It can therefore ONLY ever compute a number — there is no code
 * path that can execute code, access globals, or loop forever.
 * See REPORT.md II-A and II-D.
*/

// Only these characters may appear in a valid equation.
const ALLOWED_PATTERN = /^[0-9+\-*/().\s]+$/;

type Operator = '+' | '-' | '*' | '/';

const PRECEDENCE: Record<Operator, number> = {
  '+': 1,
  '-': 1,
  '*': 2,
  '/': 2,
};

function isOperator(token: string): token is Operator {
  return token === '+' || token === '-' || token === '*' || token === '/';
}

/**
 * Split the input into numbers, operators and parentheses.
 * Throws if it encounters anything that is not a valid token.
 */
function tokenize(input: string): string[] {
  const tokens: string[] = [];
  let i = 0;

  while (i < input.length) {
    const char = input[i];

    if (char === ' ') {
      i++;
      continue;
    }

    if (isOperator(char) || char === '(' || char === ')') {
      tokens.push(char);
      i++;
      continue;
    }

    // Accumulate a (possibly decimal) number.
    if ((char >= '0' && char <= '9') || char === '.') {
      let number = '';
      let seenDot = false;

      while (
        i < input.length &&
        ((input[i] >= '0' && input[i] <= '9') || input[i] === '.')
      ) {
        if (input[i] === '.') {
          if (seenDot) {
            throw new Error('Invalid number: multiple decimal points.');
          }
          seenDot = true;
        }
        number += input[i];
        i++;
      }

      tokens.push(number);
      continue;
    }

    // Unreachable if ALLOWED_PATTERN passed, but fail closed anyway.
    throw new Error(`Unexpected character: "${char}"`);
  }

  return tokens;
}

function applyOperator(operator: Operator, b: number, a: number): number {
  switch (operator) {
    case '+':
      return a + b;
    case '-':
      return a - b;
    case '*':
      return a * b;
    case '/':
      if (b === 0) {
        throw new Error('Division by zero.');
      }
      return a / b;
  }
}

/**
 * Safely evaluate a simple arithmetic expression.
 * @throws Error with a user-friendly message if the input is not a
 *         valid, whitelisted arithmetic expression.
 */
export function safeEvaluate(rawInput: string): number {
  const input = (rawInput ?? '').trim();

  if (input.length === 0) {
    throw new Error('Equation is empty.');
  }

  if (input.length > 100) {
    throw new Error('Equation is too long.');
  }

  // Whitelist check — reject anything that is not plain arithmetic.
  if (!ALLOWED_PATTERN.test(input)) {
    throw new Error('Equation contains invalid characters.');
  }

  const tokens = tokenize(input);

  const values: number[] = [];
  // 'u' is unary negation; it has higher precedence than any binary
  // operator and consumes a single operand.
  const operators: Array<Operator | '(' | 'u'> = [];

  // Precedence including unary negation.
  const precedenceOf = (op: Operator | 'u'): number =>
    op === 'u' ? 3 : PRECEDENCE[op];

  const collapse = () => {
    const operator = operators.pop();
    if (operator === undefined || operator === '(') {
      throw new Error('Malformed expression.');
    }
    if (operator === 'u') {
      const a = values.pop();
      if (a === undefined) {
        throw new Error('Malformed expression.');
      }
      values.push(-a);
      return;
    }
    const b = values.pop();
    const a = values.pop();
    if (a === undefined || b === undefined) {
      throw new Error('Malformed expression.');
    }
    values.push(applyOperator(operator, b, a));
  };

  let previous: string | null = null;

  for (const token of tokens) {
    if (!isNaN(Number(token)) && token !== '(' && token !== ')') {
      values.push(Number(token));
    } else if (token === '(') {
      operators.push('(');
    } else if (token === ')') {
      while (operators.length && operators[operators.length - 1] !== '(') {
        collapse();
      }
      if (operators.pop() !== '(') {
        throw new Error('Mismatched parentheses.');
      }
    } else if (isOperator(token)) {
      // A + or - is unary when it opens the expression, follows '(',
      // or follows another operator (e.g. "-5" or "3*-2").
      const isUnary =
        previous === null ||
        previous === '(' ||
        isOperator(previous as string);

      if (isUnary) {
        if (token === '+') {
          // Unary plus is a no-op; skip it.
          previous = token;
          continue;
        }
        if (token === '-') {
          // Unary negation is right-associative — push without
          // collapsing lower/equal-precedence operators.
          operators.push('u');
          previous = token;
          continue;
        }
        // A unary '*' or '/' is not valid.
        throw new Error('Malformed expression.');
      }

      while (
        operators.length &&
        operators[operators.length - 1] !== '(' &&
        precedenceOf(operators[operators.length - 1] as Operator | 'u') >=
          PRECEDENCE[token]
      ) {
        collapse();
      }
      operators.push(token);
    }

    previous = token;
  }

  while (operators.length) {
    if (operators[operators.length - 1] === '(') {
      throw new Error('Mismatched parentheses.');
    }
    collapse();
  }

  if (values.length !== 1) {
    throw new Error('Malformed expression.');
  }

  const result = values[0];
  if (!isFinite(result)) {
    throw new Error('Result is not a finite number.');
  }

  return result;
}
