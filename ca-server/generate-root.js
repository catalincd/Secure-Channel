const express = require("express")
const bodyParser = require("body-parser")
const forge = require("node-forge")
const fs = require("fs")

const KEYS_FOLDER = './root/'
const PUBLIC_KEY_PATH = `${KEYS_FOLDER}/PUBLIC.PEM`
const PRIVATE_KEY_PATH = `${KEYS_FOLDER}/PRIVATE.PEM`
const CERTIFICATE_PATH = `${KEYS_FOLDER}/CERT.PEM`

const loadRootCA = (commonName, organization, country) => 
{
    // paranoia
    if(!fs.existsSync(PUBLIC_KEY_PATH) || !fs.existsSync(PRIVATE_KEY_PATH) || !fs.existsSync(CERTIFICATE_PATH))
    {
        return generateRootCA(commonName, organization, country)
    }

    return {
        certificate: forge.pki.certificateFromPem(fs.readFileSync(CERTIFICATE_PATH)),
        publicKey: forge.pki.publicKeyFromPem(fs.readFileSync(PUBLIC_KEY_PATH)),
        privateKey: forge.pki.privateKeyFromPem(fs.readFileSync(PRIVATE_KEY_PATH))
    }
}


const generateRootCA = (commonName, organization, country) => 
{
    const rootKeyPair = forge.pki.rsa.generateKeyPair(2048);
    const rootCert = forge.pki.createCertificate();

    rootCert.publicKey = rootKeyPair.publicKey;
    rootCert.serialNumber = "01";
    rootCert.validity.notBefore = new Date();
    rootCert.validity.notAfter = new Date();
    rootCert.validity.notAfter.setFullYear(rootCert.validity.notBefore.getFullYear() + 10);

    const attrs = [
      { name: "commonName", value: commonName },
      { name: "organizationName", value: organization },
      { name: "countryName", value: country },
    ];
    rootCert.setSubject(attrs);
    rootCert.setIssuer(attrs);
    rootCert.setExtensions([
      { name: "basicConstraints", cA: true },
      { name: "keyUsage", keyCertSign: true, digitalSignature: true },
      { name: "subjectKeyIdentifier" },
    ]);

    rootCert.sign(rootKeyPair.privateKey, forge.md.sha1.create());

    fs.writeFileSync(PUBLIC_KEY_PATH, forge.pki.publicKeyToPem(rootKeyPair.publicKey));
    fs.writeFileSync(PRIVATE_KEY_PATH, forge.pki.privateKeyToPem(rootKeyPair.privateKey));
    fs.writeFileSync(CERTIFICATE_PATH, forge.pki.certificateToPem(rootCert));
    
    return {
        certificate: rootCert, 
        publicKey: rootKeyPair.publicKey, 
        privateKey: rootKeyPair.privateKey
    }
}

module.exports = {loadRootCA}