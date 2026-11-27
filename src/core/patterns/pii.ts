// Personal data and card numbers (06, chapter 4.13; 07-REQ-13): e-mail addresses, PESEL numbers,
// E.164 phone numbers and payment card numbers with a valid Luhn check digit and BIN. Pure.

/** An e-mail address in text. */
export const EMAIL_IN_TEXT =
  /(?<![\w.%+-])[A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,24}(?![\w-])/g;
const EMAIL = /^[A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,24}$/;

/** A whole value that is an e-mail address. */
export function isEmail(value: string): boolean {
  return EMAIL.test(value);
}

/** An E.164 phone number: `+` and 8 to 15 digits. */
const PHONE = /^\+[1-9]\d{7,14}$/;
/** An E.164 phone number in text, not part of a longer number. */
export const PHONE_IN_TEXT = /(?<![\w+])\+[1-9]\d{7,14}(?!\d)/g;

export function isPhone(value: string): boolean {
  return PHONE.test(value);
}

const PESEL_WEIGHTS = [1, 3, 7, 9, 1, 3, 7, 9, 1, 3];

/** A PESEL number: 11 digits with a valid check digit and a valid date of birth (06, chapter 4.14). */
export function isPesel(value: string): boolean {
  if (!/^\d{11}$/.test(value)) return false;
  const d = [...value].map(Number);
  const sum = PESEL_WEIGHTS.reduce((acc, w, i) => acc + w * (d[i] ?? 0), 0);
  if ((10 - (sum % 10)) % 10 !== d[10]) return false;
  const yy = (d[0] ?? 0) * 10 + (d[1] ?? 0);
  let month = (d[2] ?? 0) * 10 + (d[3] ?? 0);
  const day = (d[4] ?? 0) * 10 + (d[5] ?? 0);
  // The century is encoded in the month: +80 (1800s), +0 (1900s), +20, +40, +60 (2000s … 2200s).
  const century = [1900, 2000, 2100, 2200, 1800][Math.floor(month / 20)];
  if (century === undefined) return false;
  month %= 20;
  if (month < 1 || month > 12 || day < 1) return false;
  const year = century + yy;
  const days = new Date(Date.UTC(year, month, 0)).getUTCDate();
  return day <= days;
}

/** 11 digits not part of a longer number: a PESEL candidate in text. */
export const PESEL_IN_TEXT = /(?<![\d])\d{11}(?![\d])/g;

/** The Luhn check of a digit string. */
export function luhn(digits: string): boolean {
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i -= 1) {
    let n = digits.charCodeAt(i) - 48;
    if (double) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    double = !double;
  }
  return digits.length > 0 && sum % 10 === 0;
}

export type CardBrand = 'visa' | 'mastercard' | 'amex' | 'discover' | 'jcb';

/** The brand of a card number by BIN prefix and length (06, chapter 4.13), or undefined. */
export function cardBrand(digits: string): CardBrand | undefined {
  const n = digits.length;
  const p2 = Number(digits.slice(0, 2));
  const p3 = Number(digits.slice(0, 3));
  const p4 = Number(digits.slice(0, 4));
  if (digits.startsWith('4')) return n === 13 || n === 16 || n === 19 ? 'visa' : undefined;
  if ((p2 >= 51 && p2 <= 55) || (p4 >= 2221 && p4 <= 2720)) {
    return n === 16 ? 'mastercard' : undefined;
  }
  if (p2 === 34 || p2 === 37) return n === 15 ? 'amex' : undefined;
  if (p4 === 6011 || (p3 >= 644 && p3 <= 649) || p2 === 65) {
    return n >= 16 && n <= 19 ? 'discover' : undefined;
  }
  if (p4 >= 3528 && p4 <= 3589) return n >= 16 && n <= 19 ? 'jcb' : undefined;
  return undefined;
}

/** A card number: a known brand and length with a valid Luhn check digit. */
export function cardNumber(digits: string): CardBrand | undefined {
  if (!/^\d{13,19}$/.test(digits) || !luhn(digits)) return undefined;
  return cardBrand(digits);
}

/**
 * Card number candidates in text (06, chapter 4.14): 13 to 19 digits in a row, groups of 4 digits
 * split by the same space or dash (the last group shorter), or Amex 4-6-5; not next to other
 * digits.
 */
export const CARD_IN_TEXT =
  /(?<![\d])(?:\d{13,19}|\d{4}([ -])\d{4}\1\d{4}\1\d{1,4}(?:\1\d{1,3})?|3[47]\d{2}([ -])\d{6}\2\d{5})(?![\d]|[ -]\d)/g;

/** Known test card numbers of payment providers (Stripe, Braintree, Adyen), skipped by default. */
export const TEST_CARDS: ReadonlySet<string> = new Set([
  '4242424242424242',
  '4000056655665556',
  '4111111111111111',
  '4012888888881881',
  '4222222222222',
  '4000000000000002',
  '4000000000009995',
  '4000000000003220',
  '4000002500003155',
  '4917610000000000',
  '4988438843884305',
  '4166676667666746',
  '5555555555554444',
  '5200828282828210',
  '5105105105105100',
  '5454545454545454',
  '2223003122003222',
  '2222400070000005',
  '378282246310005',
  '371449635398431',
  '370000000000002',
  '6011111111111117',
  '6011000990139424',
  '6011601160116611',
  '6445644564456445',
  '3530111333300000',
  '3566002020360505',
  '3566111111111113',
]);
