import { ENCRYPT_RETURNS } from "./constants";
import * as CripToe from "./CripToe";

export const calcAge = (anniversary: string): number =>
  Math.round(
    Math.abs(new Date(anniversary).getTime() - new Date().getTime()) /
      8.64e7 /
      365,
  );

export const ranNumG = (max: number): number => Math.floor(Math.random() * max);

export const makeArray = (
  maxIndex: number,
  useKeysBool?: boolean,
): number[] => {
  if (useKeysBool) {
    return [...Array(maxIndex).keys()].map((x) => ++x);
  } else {
    return [...Array(maxIndex).keys()];
  }
};

export const shuffle = (inputArr: number[]): number[] => {
  const applyShuffler = () => {
    let len = inputArr.length;
    while (len) {
      const ran = ranNumG(len--);
      [inputArr[ran], inputArr[len]] = [inputArr[len], inputArr[ran]];
    }
    return inputArr;
  };
  return applyShuffler();
};

export const getLanguage = (): string => {
  if (navigator.languages && navigator.languages.length) {
    return navigator.languages[0];
  } else {
    return navigator.language || "en";
  }
};

export const sleep = (time: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, time * 1000));

export const normalizeEpochDate = (
  dateString: ConstructorParameters<typeof Date>[0],
): string => {
  const date = new Date(dateString);
  const format: Parameters<Date["toLocaleTimeString"]>[1] = {
    month: "long",
    day: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  };
  return `${date.toLocaleTimeString("en-US", format)}`;
};

export function isBase64(str: string): boolean {
  const notBase64 = /[^A-Z0-9+\/=]/i;
  const len = str.length;
  if (!len || len % 4 !== 0 || notBase64.test(str)) {
    return false;
  }
  const firstPaddingChar = str.indexOf("=");
  return (
    firstPaddingChar === -1 ||
    firstPaddingChar === len - 1 ||
    (firstPaddingChar === len - 2 && str[len - 1] === "=")
  );
}

const Utils = {
  ENCRYPT_RETURNS,
  CripToe,
  calcAge,
  ranNumG,
  makeArray,
  shuffle,
  getLanguage,
  sleep,
  normalizeEpochDate,
  isBase64,
};
export default Utils;
