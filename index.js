const express = require('express')
const cors = require('cors')
const cookieParser = require('cookie-parser')
const myql2 = require("mysql2/promise")
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const emailValidator = require('node-email-verifier');

//(*)_(*)//
const PORT = 3000;
const HOST = 'localhost'
const JWT_SECRET = 'qwertzuiop'
const JWT_EXPIRES_IN = '7d'
const COOKIE_NAME = 'auth_token'


// Süti_Settings :D //
const COOKIE_OPTS = {
    httpOnly: true,
    secure: false,
    sameSite: 'lax',
    path: '/',
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7-nap
}


const db = myql2.createPool({
    host: 'localhost',
    port: '3306',
    user: 'root',
    password: '',
    database: 'szavazas'
})


// --APP-- //
const app = express();
app.use(express.json())
app.use(cookieParser())
app.use(cors({
    origin: "*",
    credentials: true
}))



// Végpontok //
app.post('/regisztrácio', async (req, res) => {
    const { email, felhasználonev, jelszo, admin } = req.body;
    if (!email || !felhasználonev || !jelszo || !admin) {
        return res.status(400).json({ message: "Hiányzó adatok" })
    }
    try {
        const isValid = await emailValidator(email)
        if (!isValid) {
            return res.status(401).json({ message: 'Nem valós emailt adtál meg :(' })
        }

        const emailFelhasznalonevSQL = 'SELECT * FROM felhasznalok WHERE felhasznalok.email = ? OR felhasznalonev = ?'
        const [exist] = await db.query(emailFelhasznalonevSQL, [email, felhasználonev]);
        if (exist.length) {
            return res.status(402).json({ message: 'Az email cim vagy Felhasználónév mar foglalt' })
        }

        const hash = await bcrypt.hash(jelszo, 10);
        const regisztrácioSQL = 'INSERT INTO felhasznalok (email, felhasznalonev, jelszo, admin) VALUES (?,?,?,?)'
        const result = await db.query(regisztrácioSQL, [email, felhasználonev, hash, admin])

        return res.status(200).json({
            message: "Sikeres regisztráció",
            id: result.insertId
        })

    } catch (error) {
        console.log(error)
        return res.status(500).json({ message: "Szerverhiba" })
    }
})

app.post('/belepes', async (req, res) => {
    const { felhasználonevVagyEmail, jelszo } = req.body;
    if (!felhasználonevVagyEmail || !jelszo) {
        return res.status(400).json({ message: "Hiányos belépési adatok" })
    }

    try {
        const isValid = await emailValidator(felhasználonevVagyEmail)
        let hashJelszo = "";
        let user = {}
        if (isValid) {
            const sql = 'SELECT * FROM felhasznalok WHERE email = ?'
            const [rows] = await db.query(sql, [felhasználonevVagyEmail]);
            if (rows.length) {
                user = rows[0];
                hashJelszo = user.jelszo
            } else {
                return res.status(400).json({ message: "Ezzel az email címel meg nem regisztráltak" })
            }

        } else {
            const sql = 'SELECT * FROM felhasznalok WHERE felhasznalonev = ?'
            const [rows] = await db.query(sql, [felhasználonevVagyEmail]);
            if (rows.length) {
                user = rows[0];
                hashJelszo = user.jelszo
            } else {
                return res.status(400).json({ message: "Ezzel a felhasznalonevvel meg nem regisztráltak" })
            }
        }
        const ok = bcrypt.compare(jelszo, hashJelszo)
        if (!ok) {
            return res.status(403).json({message: "Rossz jelszot adtal meg!"})
        }
        if (ok) {
            const token = jwt.sign(
                { id: user.id, email: user.email, felhasználonev: user.felhasználonev, admin: user.admin },
                JWT_SECRET,
                { expiresIn: JWT_EXPIRES_IN }
                )
            }

            res.cookie(COOKIE_NAME, token, COOKIE_OPTS)
            res.status(200).json({message: "Sikeres Belépés"})
    } catch (error) {
    console.log(error)
    return res.status(500).json({ message: "Szerverhiba" })
}
})



// Védett
app.get('/adataim',auth, async (req, res) => {
})


// Szero inditasa //
app.listen(PORT, HOST, () => {
    console.log(`API fut: http://${HOST}:${PORT}/`)
})
