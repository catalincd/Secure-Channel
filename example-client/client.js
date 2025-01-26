const forge = require("node-forge")
const fs = require("fs")
const readline = require('readline')
const axios = require('axios')
const crypto = require('crypto')
const { exit } = require("process")


let caHostname = ""
let serverHostname = ""
let id = ""

const key = crypto.randomBytes(32)
const iv = crypto.randomBytes(16)

const encrypt = (text, key, iv) => {
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}

const decrypt = (encryptedText, key, iv) => {
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv)
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
})

rl.question('Please enter CA Server (defaults to localhost:7017):', (hostname) => {
    caHostname = hostname.length > 2 ? hostname : "localhost:7017"

    rl.question('Please enter Example Server (defaults to localhost:7018):', (sv_hostname) => {
        serverHostname = sv_hostname.length > 2 ? sv_hostname : "localhost:7018"
        connectToServer()
    });
});

const connectToServer = async () => {
    let sv_cert = null
    await axios.post(`http://${serverHostname}/connect`, { message: "hello" }, { 'Content-Type': 'application/json' })
        .then(response => {
            sv_cert = response.data.certificate
            id = response.data.id
        })
        .catch(error => {
            console.error('Error:', error.response ? error.response.data : error.message)
            exit(1)
        })

    let validated = false
    await axios.post(`http://${caHostname}/verify-certificate`, { certificate: sv_cert }, { 'Content-Type': 'application/json' })
        .then(response => {
            validated = response.data.valid
            if (!validated) {
                console.error('Error:', response.data.reason)
                exit(1)
            }
        })
        .catch(error => {
            console.error('Error:', error.response ? error.response.data : error.message)
            exit(1)
        })

    const CERT_OBJ = forge.pki.certificateFromPem(sv_cert)
    const encrypt3d = CERT_OBJ.publicKey.encrypt(JSON.stringify({ key, iv }))

    await axios.post(`http://${serverHostname}/send-sym-key`, { id, key: encrypt3d }, { 'Content-Type': 'application/json' })
        .then(response => {
            console.log(response.data)
        })
        .catch(error => {
            console.error('Error:', error.response ? error.response.data : error.message)
            exit(1)
        })

    startConnection()
}

const startReading = () => {
    rl.question('', (input) => {
        if (input === 'eXit') { //ikyk
            console.log('Goodbye!')
            exit(1)
        }

        const encrypt3dMessage = encrypt(input, key, iv)

        axios.post(`http://${serverHostname}/send-message`, { id, message: encrypt3dMessage }, { 'Content-Type': 'application/json' })
            .then(response => {
                // console.log(response.data)
            })
            .catch(error => {
                console.error('Error:', error.response ? error.response.data : error.message)
                exit(1)
            })

        startReading()
    })
}

const printed = []

const printMessages = (messages) => {
    const decrypt3dMessages = JSON.parse(decrypt(messages, key, iv))

    decrypt3dMessages.forEach(msg => {
        if (!printed.includes(msg.id) && msg.user != id) {
            console.log(`${msg.user}: ${msg.text}`)
            printed.push(msg.id)
        }
    });
}

const updateMessages = () => {
    axios.post(`http://${serverHostname}/update-messages`, { id }, { 'Content-Type': 'application/json' })
        .then(response => {
            printMessages(response.data.messages)
        })
        .catch(error => {
            console.error('Error:', error.response ? error.response.data : error.message)
            exit(1)
        })
}

const startConnection = () => {
    startReading()
    setInterval(updateMessages, 1000)
}