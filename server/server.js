import express from "express"
import cors from "cors"
import 'dotenv/config'
import cookieParser from "cookie-parser"
import authRouter from './routes/authRouter.js'

import connectDB from './config/mongodb.js'
import userRouter from "./routes/userRoutes.js"

const app = express()
const port = process.env.PORT || 4000

const allowedOrigins = ['http://localhost:5173']

connectDB()
app.use(express.json())
app.use(cookieParser())
app.use(cors({origin:allowedOrigins, credentials: true }))

app.use('/api/auth', authRouter)
app.use('/api/user', userRouter)



app.get('/', (req, res) => {
    res.send("API working ")
})

app.listen(port, () => { console.log(`Server started on PORT : ${port}`) })