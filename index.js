export const themeColors = {
    errormessage: "#9f0000",
    errorbackground: "#ffeeee",
};
export const calcAge = (anniversary) => Math.round(Math.abs(new Date(anniversary).getTime() - new Date().getTime()) /
    8.64e7 /
    365);
export const D1Tables = {
    Group_Photos: "Group_Photos",
    Headshots_Sm: "Headshots_Sm",
    Headshots_Lg: "Headshots_Lg",
    Litters: "Litters",
    Dogs: "Dogs",
    Adults: "Adults",
    Puppies: "Puppies",
    Families: "Families",
    Dog_To_Group_Photos: "Dog_To_Group_Photos",
};
export const D1Columns = {
    Group_Photos: {
        id: "id",
        groupPhotos: "groupPhotos",
    },
    Headshots_Sm: {
        id: "id",
        headshotSmall: "headshotSmall",
    },
    Headshots_Lg: {
        id: "id",
        headshotLarge: "headshotLarge",
    },
    Litters: {
        id: "id",
        dueDate: "dueDate",
        birthday: "birthday",
        applicantsInQueue: "applicantsInQueue",
    },
    Dogs: {
        id: "id",
        gender: "gender",
        noseColor: "noseColor",
        coatColor: "coatColor",
        personality: "personality",
        headshotSmall: "headshotSmall",
        headshotLarge: "headshotLarge",
    },
    Adults: {
        id: "id",
        adultName: "adultName",
        breeder: "breeder",
        birthday: "birthday",
        eyeColor: "eyeColor",
        isRetired: "isRetired",
        about: "about",
        weight: "weight",
        energyLevel: "energyLevel",
        dogId: "dogId",
    },
    Puppies: {
        id: "id",
        puppyName: "puppyName",
        collarColor: "collarColor",
        isAvailable: "isAvailable",
        dogId: "dogId",
        litterId: "litterId",
    },
    Families: {
        id: "id",
        groupPhoto: "groupPhoto",
        mother: "mother",
        father: "father",
        litterId: "litterId",
    },
    Dog_To_Group_Photos: {
        id: "id",
        groupPhotoId: "groupPhotoId",
        dogId: "dogId",
    },
};
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
const Utils = {
    themeColors,
    calcAge,
    ranNumG,
    makeArray,
    shuffle,
    getLanguage,
    sleep,
    normalizeEpochDate,
};
export default Utils;
