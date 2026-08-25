import { describe, expect, it } from "vitest";
import { passwordStrength } from "../client/src/lib/passwordStrength";

describe("passwordStrength", () => {
  it("rewards length and character diversity", () => { expect(passwordStrength("short")).toBe(0); expect(passwordStrength("long enough password")).toBeGreaterThanOrEqual(2); expect(passwordStrength("Long enough 123! password")).toBe(4); });
  it("penalizes repeated characters", () => { expect(passwordStrength("aaaaaaaaaaaaaaaa")).toBe(1); });
});
