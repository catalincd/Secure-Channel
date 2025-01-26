const forge = require("node-forge")
const crypto = require('crypto')
const fs = require('fs')

const getGenericDigest = () => {
    const digest = forge.md.sha256.create()
    return digest
}

const getDigest = (cert) => {
    const digest = forge.md.sha256.create();
    digest.update(forge.asn1.toDer(forge.pki.getTBSCertificate(cert)).getBytes())
    return digest
}

const loadOrCreate = (PATH, enc) => {
    try{
        const stream = fs.readFileSync(REVOKED_PATH, enc)
        return stream.toString()
    }
    catch(e){
        fs.writeFileSync(PATH, "")
    }

    return ""
}

module.exports = { getDigest, getGenericDigest, loadOrCreate }