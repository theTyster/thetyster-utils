import { describe, test, expect } from "vitest";
import {
  calcAge,
  ranNumG,
  makeArray,
  shuffle,
  getLanguage,
  sleep,
  normalizeEpochDate,
  isBase64,
} from "../dist/thetyster-utils";

describe("Utils", () => {
  test("should be defined", () => {
    expect(calcAge).toBeDefined();
    expect(ranNumG).toBeDefined();
    expect(makeArray).toBeDefined();
    expect(shuffle).toBeDefined();
    expect(getLanguage).toBeDefined();
    expect(sleep).toBeDefined();
    expect(normalizeEpochDate).toBeDefined();
    expect(isBase64).toBeDefined();
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
        "December 12, 2012 at 11:59 PM",
      );
    });
  });
});

describe("mightBeBase64", () => {
  test("should return true if the string might be base64", () => {
    expect.soft(isBase64("dGVzdA7r5f6gDgh4bxao+l==")).toBe(true);
    expect.soft(isBase64("7r5f6grMv4hDgh4tosp/lg==")).toBe(true);
    expect.soft(isBase64("hsFMy8Hk604LHf0En+e/sA==")).toBe(true);
    expect.soft(isBase64("yR6au1Ag/NysRMznd9x7mQ==")).toBe(true);
    expect.soft(isBase64("Xzs92E7PY0eGbY7LrxV6uQ==")).toBe(true);
    expect.soft(isBase64("k8t3lvtKjWw57VgzZvKDnA==")).toBe(true);
    expect.soft(isBase64("IApEOKTa6dc45/4zBnEz7g==")).toBe(true);
    expect.soft(isBase64("Q4xj6s3GtMvM8zX2z6g9GQ==")).toBe(true);
  });

  test("should return false if the string is not base64", () => {
    expect(isBase64("----")).toBe(false);
    expect(isBase64("____")).toBe(false);
    expect(isBase64("....")).toBe(false);
  });
});
