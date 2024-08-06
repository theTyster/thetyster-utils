import * as C from "./CripToe.js";
export const CripToe = C.default;
export const calcAge = (anniversary) => Math.round(Math.abs(new Date(anniversary).getTime() - new Date().getTime()) /
    8.64e7 /
    365);
export const ranNumG = (max) => Math.floor(Math.random() * max);
export const makeArray = (maxIndex, useKeysBool) => {
    if (useKeysBool) {
        return [...Array(maxIndex).keys()].map((x) => ++x);
    }
    else {
        return [...Array(maxIndex).keys()];
    }
};
export const shuffle = (inputArr) => {
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
export const getLanguage = () => {
    if (navigator.languages && navigator.languages.length) {
        return navigator.languages[0];
    }
    else {
        return navigator.language || "en";
    }
};
export const sleep = (time) => new Promise((resolve) => setTimeout(resolve, time * 1000));
export const normalizeEpochDate = (dateString) => {
    const date = new Date(dateString);
    const format = {
        month: "long",
        day: "numeric",
        year: "numeric",
        hour: "2-digit",
        minute: "2-digit",
    };
    return `${date.toLocaleTimeString("en-US", format)}`;
};
export function isBase64(str) {
    const notBase64 = /[^A-Z0-9+\/=]/i;
    const len = str.length;
    if (!len || len % 4 !== 0 || notBase64.test(str)) {
        return false;
    }
    const firstPaddingChar = str.indexOf("=");
    return (firstPaddingChar === -1 ||
        firstPaddingChar === len - 1 ||
        (firstPaddingChar === len - 2 && str[len - 1] === "="));
}
const Utils = {
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
