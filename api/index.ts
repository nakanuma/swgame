import express from "express";
import { PrismaClient } from "@prisma/client"
import { createHash, randomBytes } from "crypto";
import jwt from "jsonwebtoken";
import config from "./config";
import { PrismaPg } from "@prisma/adapter-pg";
import { Pool } from "pg";
import "dotenv/config";

const app: express.Express = express();
const PORT = 3000;

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const adapter = new PrismaPg(pool);
const prisma = new PrismaClient({ adapter });

app.use(express.json());

app.listen(PORT, () => {
    console.log("Server is running on PORT:", PORT);
});

app.get("/scores", VerifyToken, async (_: express.Request, res: express.Response) : Promise<void> => {
    const scores = await prisma.score.findMany({
        orderBy: [
            {
                score: 'desc'
            }
        ],
        include: { user: true },
        take: 5,
    });
    res.json(scores);
});

app.post("/scores", VerifyToken, async (req: express.Request, res: express.Response) : Promise<void> =>{
    const { score } = req.body;
    const user: any = await GetUser(req);

    const result = await prisma.score.create({
        data: {
            userId: user.id,
            score: score
        },
    });

    if (result != null) {
        res.json({ status_code: 200 });
    } else {
        res.json({ status_code: 500 });
    }
});

app.post("/users/new", async (req: express.Request, res: express.Response): Promise<void> => {
    const name = req.body.name;
    const salt = randomBytes(8).toString('hex');

    const password = createHash('sha256').update(req.body.password + salt + config.pepper, 'utf8').digest('hex');

    const result = await prisma.user.create({
        data: {
            name,
            password,
            salt
        },
    });

    res.json(result);
}); 

app.post("/users/login", async (req: express.Request, res: express.Response) : Promise<void> => {
    const { name, password } = req.body;

    const saltres: any = await prisma.user.findFirst({
        where: {
            name: name
        }
    });

    if(saltres != null) {
        const salt: any = saltres.salt;
        const password = createHash('sha256').update(req.body.password + salt + config.pepper, 'utf8').digest('hex');
        const result: any = await prisma.user.findFirst({
        where: {
            name: name,
            password: password
        }
    });

    if(result != null) {
        const token = jwt.sign({ name: name }, config.jwt_secret || "", { expiresIn: '1h' });

        res.json({login_status: "success", token: token});
    } else {
        res.json({login_status: "faild"});
    }
    } else {
        res.json({ login_status: "No User found."});
    }
});

async function VerifyToken(req: express.Request, res: express.Response, next: any) {
    const authHeader = req.headers["authorization"];
    if(authHeader != undefined) {
        if(authHeader.split(" ")[0] == "Bearer") {
            try{
                const token = jwt.verify(authHeader.split(" ")[1], config.jwt_secret || "") as jwt.JwtPayload;

                const result = await prisma.user.findFirst({
                    where: {
                        name: token.name,
                    }
                });

                if (result != null && token.exp && Date.now() < token.exp * 1000) {
                    console.log(token);
                    next();
                } else {
                    res.json({ error: "auth error" });
                }
            } catch (e: any) {
                // tokenエラー
                console.log(e.message);
                res.json({ error: e.message });
            }
        } else {
            res.json({ error: "header format error" });
        }
    } else {
        res.json({ error: "header error" });
    }
}

async function GetUser(req: express.Request): Promise<any> {
    const authHeader = req.headers["authorization"];
    if(authHeader !== undefined) {
        if(authHeader.split(" ")[0] === "Bearer") {
            try {
                const token = jwt.verify(authHeader.split(" ")[1], config.jwt_secret || "") as jwt.JwtPayload;
                const result: any = await prisma.user.findFirst(
                    {
                        where: {
                            name: token.name,
                        }
                    }
                );

                if(result != null && token.exp && Date.now() < token.exp * 1000) {
                    return result
                }
            } catch (e: any) {
                console.log(e.message);
            }
        }
    }
    return {};
}

export default app;