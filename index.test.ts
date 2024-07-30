import { describe, test, expect } from "vitest";
import Utils, {
  calcAge,
  ranNumG,
  makeArray,
  shuffle,
  getLanguage,
  sleep,
  normalizeEpochDate,
} from "./index.js";

describe("Utils", () => {
  test("should be defined", () => {
    const u = Utils;
    expect(u.calcAge).toBeDefined();
    expect(u.ranNumG).toBeDefined();
    expect(u.makeArray).toBeDefined();
    expect(u.shuffle).toBeDefined();
    expect(u.getLanguage).toBeDefined();
    expect(u.sleep).toBeDefined();
    expect(u.normalizeEpochDate).toBeDefined();
  });

  describe("calcAge", () => {
    test("should return the correct age", () => {
      expect(calcAge("1990-09-01")).toBe(34);
    });
  });

  describe("ranNumG", () => {
    test("should return a random number", () => {
      expect(ranNumG(10)).toBeGreaterThanOrEqual(0);
      expect(ranNumG(10)).toBeLessThanOrEqual(10);
    });
  });

  describe("makeArray", () => {
    test("should return an array of numbers", () => {
      expect(makeArray(6)).toMatchInlineSnapshot([0, 1, 2, 3, 4, 5]);
    });
  });

  describe("shuffle", () => {
    test("should shuffle an array", () => {
      expect(shuffle([1, 2, 3, 4, 5])).not.toEqual([1, 2, 3, 4, 5]);
    });
  });

  describe.todo("getLanguage", () => {
    test("should return the correct language", () => {
      expect(getLanguage()).toBe("en");
    });
  });

  describe("sleep", () => {
    test("should resolve after a certain amount of time", async () => {
      const start = Date.now();
      await sleep(0.01);
      const end = Date.now();
      expect(end - start).toBeGreaterThanOrEqual(10);
    });
  });

  describe("normalizeEpochDate", () => {
    test("should return a formatted date string", () => {
      expect(normalizeEpochDate("2012-12-12 23:59:00")).toBe(
        "December 12, 2012 at 11:59 PM"
      );
    });
  });
});

