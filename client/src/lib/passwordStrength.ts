export function passwordStrength(value: string): number {
  let score = 0;
  if (value.length >= 12) score++;
  if (value.length >= 16) score++;
  if (/[a-z]/.test(value) && /[A-Z]/.test(value)) score++;
  if (/\d/.test(value) && /[^A-Za-z0-9]/.test(value)) score++;
  if (/(.)\1{2,}/.test(value)) score = Math.max(0, score - 1);
  return score;
}
