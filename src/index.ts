import { createConnection} from "typeorm"
import express, { application } from "express"
import dotenv from "dotenv";
dotenv.config()
import { Users } from "./entities/Users"
import { createUserRouter } from "./routes/create_user"

const app = express()

const main = async () => {
    try {
        await createConnection({
            type: "postgres",
            url: process.env.DATABASE_URL,
            "ssl": true,
            "entities": [Users],
            synchronize: true,
            "extra": {
                "ssl": {
                "rejectUnauthorized": false
                }
            }
        })
        console.log("Connected to Database")
        app.use(express.json())
        app.use(createUserRouter)

        app.listen(8080, () => {
            console.log(`Port is running on port 8080`);
            
        })
        
    } catch (error) {
        console.error(error)
        console.log("Unable to connect")
    }
}

main()