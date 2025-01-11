const forge = require("node-forge")
const crypto = require('crypto');

const getGenericDigest = () => {
    const digest = forge.md.sha256.create()
    return digest
}

const getDigest = (cert) => {
    const digest = forge.md.sha256.create();
    digest.update(forge.asn1.toDer(forge.pki.getTBSCertificate(cert)).getBytes());
    return digest
}

module.exports = { getDigest, getGenericDigest }