const express = require("express")
const bodyParser = require("body-parser")
const forge = require("node-forge")
const fs = require("fs")

const { loadRootCA } = require("./src/generate-root")
const { getDigest, getGenericDigest} = require("./src/utils")

const app = express()
app.use(bodyParser.json())


const ROOT = loadRootCA("Trusted Authority", "WUT", "RO")
const CA_STORE = forge.pki.createCaStore([])

let rootPublicKey = ROOT.publicKey
let rootPrivateKey = ROOT.privateKey
let rootCertificate = ROOT.certificate

const sha256Digest = getGenericDigest()
const revoked = fs.readFileSync("revoked.txt", 'ascii').toString().split('\n')

app.post("/issue-certificate", (req, res) => {
    try {
        if (!rootCertificate || !rootPublicKey || !rootPrivateKey) {
            return res.status(400).json({ error: "Root certificate not generated." })
        }

        const { commonName, organization, country } = req.body

        const keyPair = forge.pki.rsa.generateKeyPair(2048)
        const cert = forge.pki.createCertificate()
        

        cert.publicKey = keyPair.publicKey
        cert.serialNumber = Date.now().toString()

        cert.validity.notBefore = new Date()
        cert.validity.notAfter = new Date()
        cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1)


        const attrs = [
            { name: "commonName", value: commonName },
            { name: "organizationName", value: organization },
            { name: "countryName", value: country },
        ]

        cert.setSubject(attrs)
        cert.setIssuer(rootCertificate.subject.attributes)        
        cert.sign(rootPrivateKey, sha256Digest)

        res.json({
            message: "Certificate issued successfully.",
            certificate: forge.pki.certificateToPem(cert),
            privateKey: forge.pki.privateKeyToPem(keyPair.privateKey),
        })
    } catch (error) {
        console.log(error)
        res.status(500).json({ error: "Failed to issue certificate:" + error })
    }
})

app.post("/verify-certificate", (req, res) => {
    try {
        const cert = forge.pki.certificateFromPem(req.body.certificate)

        const now = new Date()
        if (now < cert.validity.notBefore || now > cert.validity.notAfter) {
            return res.json({ valid: false, reason: "Certificate is expired or not yet valid." })
        }

        
        if (JSON.stringify(cert.issuer.attributes) !== JSON.stringify(rootCertificate.subject.attributes)) {
            return res.json({ valid: false, reason: "Issuer does not match the root certificate." })
        }

        const validSignature = rootPublicKey.verify(
            getDigest(cert).digest().getBytes(),
            cert.signature
        )
        
        if (!validSignature) {
            return res.json({ valid: false, reason: "Invalid certificate signature." })
        }

        const digestHex = getDigest(cert).digest().toHex()
        console.log(digestHex)
        if(revoked.some(hash => hash == digestHex)) {
            return res.json({ valid: false, reason: "Revoked certificate." })
        }

        return res.json({ valid: true, reason: "Certificate is valid." })
    } catch (error) {
        console.log(error)
        return res.json({ valid: false, reason: `Validation failed: ${error.message}` })
    }
})

app.post("/renew-certificate", (req, res) => {
    res.json({ "error": "Not implemented" })
})

app.post("/revoke-certificate", (req, res) => {
    res.json({ "error": "Not implemented" })
})


const PORT = 7017
app.listen(PORT, () => {
    console.log(`Certificate Authority server running on http://localhost:${PORT}`)
})
