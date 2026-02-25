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
    origin: 'http://localhost:5173',
    credentials: true
}))




function auth(req, res, next) {
    const token = req.cookies[COOKIE_NAME];
    if (!token) {
        return res.status(409).json({ message: "Nem vagy bejelentkezve :D" })

    }
    try {
        req.user = jwt.verify(token, JWT_SECRET)
        next();
    } catch (error) {
        return res.status(410).json({ message: "Nem ervenyes token" })
    }
}

// Végpontok //
app.post('/regisztracio', async (req, res) => {
    const { email, felhasznalonev, jelszo, admin } = req.body;
    if (!email || !felhasznalonev || !jelszo || !(admin===0 || admin===1)) {
        return res.status(400).json({ message: "Hiányzó adatok" })
    }
    try {
        const isValid = await emailValidator(email)
        if (!isValid) {
            return res.status(401).json({ message: 'Nem valós emailt adtál meg :(' })
        }

        const emailFelhasznalonevSQL = 'SELECT * FROM felhasznalok WHERE felhasznalok.email = ? OR felhasznalonev = ?'
        const [exist] = await db.query(emailFelhasznalonevSQL, [email, felhasznalonev]);
        if (exist.length) {
            return res.status(402).json({ message: 'Az email cim vagy Felhasználónév mar foglalt' })
        }

        const hash = await bcrypt.hash(jelszo, 10);
        const regisztrácioSQL = 'INSERT INTO felhasznalok (email, felhasznalonev, jelszo, admin) VALUES (?,?,?,?)'
        const result = await db.query(regisztrácioSQL, [email, felhasznalonev, hash, admin])

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
    const { felhasznalonevVagyEmail, jelszo } = req.body;
    if (!felhasznalonevVagyEmail || !jelszo) {
        return res.status(400).json({ message: "Hiányos belépési adatok" })
    }

    try {
        const isValid = await emailValidator(felhasznalonevVagyEmail)
        let hashJelszo = "";
        let user = {}
        if (isValid) {
            const sql = 'SELECT * FROM felhasznalok WHERE email = ?'
            const [rows] = await db.query(sql, [felhasznalonevVagyEmail]);
            if (rows.length) {
                user = rows[0];
                hashJelszo = user.jelszo
            } else {
                return res.status(400).json({ message: "Ezzel az email címel meg nem regisztráltak" })
            }

        } else {
            const sql = 'SELECT * FROM felhasznalok WHERE felhasznalonev = ?'
            const [rows] = await db.query(sql, [felhasznalonevVagyEmail]);
            if (rows.length) {
                user = rows[0];
                hashJelszo = user.jelszo
            } else {
                return res.status(400).json({ message: "Ezzel a felhasznalonevvel meg nem regisztráltak" })
            }
        }
        const ok = bcrypt.compare(jelszo, hashJelszo)
        if (!ok) {
            return res.status(403).json({ message: "Rossz jelszot adtal meg!" })
        }
        if (ok) {
            const token = jwt.sign(
                { id: user.id, email: user.email, felhasznalonev: user.felhasznalonev, admin: user.admin },
                JWT_SECRET,
                { expiresIn: JWT_EXPIRES_IN }
            )
            res.cookies(COOKIE_NAME, token, COOKIE_OPTS)
            res.status(200).json({ message: "Sikeres Belépés" })
        }


    } catch (error) {
        console.log(error)
        return res.status(500).json({ message: "Szerverhiba" })
    }
})


app.post('/kijelentkezes', auth, async (req, res) => {
    res.clearCookie(COOKIE_NAME, { path: '/' });
    res.status(200).json({ message: "Sikeres kijelentkezés |_(*)__(*)_|" })
})



// Védett
app.get('/adataim', auth, async (req, res) => {
    res.status(200).json(req.user)
})



app.put('/email', auth, async (req,res)=>{
    const {ujemail} = req.body;
    if (!ujemail) {
        return res.status(401).json({message: 'Az új email megadása kötelező'})
    }
    const isValid = await emailValidator(ujemail)
    if (!isValid) {
        return res.status(402).json({message: 'Az email formatuma nem megfelelo'})
    }
    try {
        const sql1 = 'SELECT * FROM felhasznalok WHERE email = ?'
        const [result] = await db.query(sql1, [ujemail]);
        if (result.length) {
            return res.status(403).json({message: 'Az email már foglalt :('})
        }
        const sql2 = 'UPDATE felhasznalok SET email = ? WHERE id=?' 
        await db.query(sql2,[ujemail,req.user.id])
        return res.status(200).json({message: 'Sikeresen megváltozott az email'})
    } catch (error) {
            console.log(error)
            res.status(500).json({message: "Szerverhiba"})
    }
} )

app.put('/felhasznalonev', auth, async (req,res)=>{
    const {ujFelhasznalonev} = req.body;
    if (!ujFelhasznalonev) {
        return res.status(401).json({message: 'Az új FelHNev megadása kötelező'})
    }
    try {
        const sql1 = 'SELECT * FROM felhasznalok WHERE felhasznalonev = ?'
        const [result] = await db.query(sql1, [ujFelhasznalonev]);
        if (result.length) {
            return res.status(403).json({message: 'A FelHNev már foglalt :('})
        }

        const sql2 = 'UPDATE felhasznalok SET felhasznalonev = ? WHERE id=?' 
        await db.query(sql2,[ujFelhasznalonev,req.user.id])
        return res.status(200).json({message: 'Sikeresen megváltozott a felhasznalonev'})
    } catch (error) {
            console.log(error)
            res.status(500).json({message: "Szerverhiba"})
    }
})





app.put('/jelszo', async(req,res)=>{
    const {jelenelegiJelszo, ujJelszo} = req.body;
    if(!jelenelegiJelszo || ujJelszo){
        return res.status(400).json({message: "Hianyzo Adatok"})
    }
    try {
        const sql = 'SELECT * FROM felhasznalok WHERE id = ?'
        const [rows] = await db.query(sql, [req.user.id]);
        const user = rows[0]
        const hashJelszo = user.jelszo
            user = rows[0];
            hashJelszo = user.jelszo

        const ok = bcrypt.compare(jelszo, hashJelszo)
        if (!ok) {
            return res.status(401).json({message: "Helytelen jelszo"})
        }

        const hashUjJelszo = await bcrypt.hash(ujJelszo, 10);
        
        const sql2 = 'UPDATE felhasznalok SET jelszo = ? WHERE id=?' 
        await db.query(sql2,[hashUjJelszo,req.user.id])
        return res.status(200).json({message: 'Sikeresen megváltozott a jelszavad'})

    } catch (error) {
        console.log(error);
        res.status(500).json({message: "SzerverhiPPba"})
    } 
})



app.delete('/fiokom',auth, async (req,res)=>{
    try {
        const sql = 'DELETE FROM felhasznalok WHERE id = ?'
        await db.query(sql,[req.user.id])
        res.clearCookie(COOKIE_NAME, { path: '/' });
        res.status(200).json({ message: "Sikeres Fioktorles \_(*)__(*)_/" })
    } catch (error) {
        console.log(error)
        res.status(500).json({message: 'Szerverhiba'})
    }
})

// Szero inditasa //
app.listen(PORT, HOST, () => {
    console.log(`API fut: http://${HOST}:${PORT}/`)
})


