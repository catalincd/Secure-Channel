const express = require("express")
const bodyParser = require("body-parser")
const forge = require("node-forge")
const fs = require("fs")
const readline = require('readline')
const http = require('http')
const axios = require('axios')
const crypto = require('crypto')
const { exit } = require("process")

let caHostname = ""
let certificate = ""
let privateKey = ""

let PK_OBJ = null;

const PORT = 7018
const certData = {
    commonName: "Secure-Channel-Example-Server",
    organization: "WUT",
    country: "RO"
}

const clients = {}
const messages = []

const getId = (length = 8) => {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let token = '';
    for (let i = 0; i < length; i++) {
        const randomIndex = Math.floor(Math.random() * characters.length);
        token += characters.charAt(randomIndex);
    }
    return token;
}

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

const app = express()
app.use(bodyParser.json())

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
})

rl.question('Please enter CA Server (defaults to localhost:7017):', (hostname) => {
    caHostname = hostname.length > 2 ? hostname : "localhost:7017"
    startServer()
});


const startServer = () => {
    axios.post(`http://${caHostname}/issue-certificate`, certData, { 'Content-Type': 'application/json' })
        .then(response => {
            certificate = response.data.certificate
            privateKey = response.data.privateKey

            PK_OBJ = forge.pki.privateKeyFromPem(privateKey)
        })
        .catch(error => {
            console.error('Error:', error.response ? error.response.data : error.message)
            exit(1)
        })


    app.listen(PORT, () => {
        console.log(`Example server running on: http://localhost:${PORT}`)
    })
}


app.post("/connect", (req, res) => {
    try {
        res.json({
            id: getId(),
            certificate: certificate
        })
    } catch (error) {
        console.log(error)
        return res.json({ valid: false, reason: `Validation failed: ${error.message}` })
    }
})


app.post("/send-sym-key", (req, res) => {
    try {
        const {id, key} = req.body
        if(clients[id]) { // don't be like that
            return res.json({ valid: false, reason: `Id ${id} already exists` })
        }

        clients[id] = JSON.parse(PK_OBJ.decrypt(key))

        console.log(clients)

        res.json({ valid: true, reason: `Connected` })
    } catch (error) {
        console.log(error)
        return res.json({ valid: false, reason: `Validation failed: ${error.message}` })
    }
})

let msgCounter = 1

app.post("/send-message", (req, res) => {
    try {
        const {id, message} = req.body
        if(!clients[id]) { // don't be like that
            return res.json({ valid: false, reason: `Id ${id} doesn't exist` })
        }
        
        const key = Buffer.from(clients[id].key.data)
        const iv = Buffer.from(clients[id].iv.data)

        plainMessage = decrypt(message, key, iv)
        messages.push({id: msgCounter, user: id, text: plainMessage})
        msgCounter += 1

        console.log(plainMessage)

        res.json({ valid: true, reason: `Connected` })
    } catch (error) {
        console.log(error)
        return res.json({ valid: false, reason: `Validation failed: ${error.message}` })
    }
})

app.post("/update-messages", (req, res) => {
    try {
        const {id} = req.body
        if(!clients[id]) { // don't be like that
            return res.json({ valid: false, reason: `Id ${id} doesn't exist` })
        }
        
        const key = Buffer.from(clients[id].key.data)
        const iv = Buffer.from(clients[id].iv.data)
        const encrypt3dMessages = encrypt(JSON.stringify(messages), key, iv)


        res.json({ messages: encrypt3dMessages })
    } catch (error) {
        console.log(error)
        return res.json({ valid: false, reason: `Validation failed: ${error.message}` })
    }
})