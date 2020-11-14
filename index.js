const { predefined } = require("@ckb-lumos/config-manager");
const { mnemonic, ExtendedPrivateKey, key } = require("@ckb-lumos/hd");
const { generateAddress } = require("@ckb-lumos/helpers");
const fs = require("fs");
const path = require("path");

function getPath(type, index) {
  return `m/44'/309'/0'/${type}/${index}`;
}

function generateLinaAddress(blake160) {
  const template = predefined.LINA.SCRIPTS.SECP256K1_BLAKE160;
  const script = {
    code_hash: template.CODE_HASH,
    hash_type: template.HASH_TYPE,
    args: blake160,
  };
  return generateAddress(script, { config: predefined.LINA });
}

function generateAggron4Address(blake160) {
  const template = predefined.AGGRON4.SCRIPTS.SECP256K1_BLAKE160;
  const script = {
    code_hash: template.CODE_HASH,
    hash_type: template.HASH_TYPE,
    args: blake160,
  };
  return generateAddress(script, { config: predefined.AGGRON4 });
}

function generateInfo(extendedPrivateKey, type, index) {
  const path = getPath(type, index);
  const info = extendedPrivateKey.privateKeyInfoByPath(path);
  const blake160 = key.publicKeyToBlake160(info.publicKey);
  const linaAddress = generateLinaAddress(blake160);
  const aggron4Address = generateAggron4Address(blake160);

  return {
    ...info,
    blake160,
    linaAddress,
    aggron4Address,
  };
}

function generateInfos(extendedPrivateKey, count) {
  const infos = [];
  for (let i = 0; i < count; i++) {
    const receivingInfo = generateInfo(extendedPrivateKey, 0, i);
    const changeInfo = generateInfo(extendedPrivateKey, 1, i);

    infos.push(receivingInfo);
    infos.push(changeInfo);
  }
  return infos;
}

const file = process.argv[2];
const count = process.argv[3] || 30;
const outputFile = process.argv[4] || "keys.json";
const mne = fs.readFileSync(path.resolve(file), "utf8").trim();

const seed = mnemonic.mnemonicToSeedSync(mne);
const extendedPrivateKey = ExtendedPrivateKey.fromSeed(seed);

const infos = generateInfos(extendedPrivateKey, +count);

let data = JSON.stringify(infos, null, 2);
fs.writeFileSync(path.resolve(outputFile), data);
