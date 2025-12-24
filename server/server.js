const jwt = require("jsonwebtoken")
const bcrypt = require("bcryptjs")
const { MongoClient, ObjectId } = require("mongodb")
const io = require("socket.io")(3001, {
    cors: {
        origin: 'http://localhost:3000',
        methods: ['GET', 'POST'],
    },
})

const JWT_SECRET = process.env.JWT_SECRET || "dev-secret"
const MONGODB_URI = process.env.MONGODB_URI || "mongodb://127.0.0.1:27017"
const MONGODB_DB = process.env.MONGODB_DB || "doceditor"
const BCRYPT_ROUNDS =
    Number.parseInt(process.env.BCRYPT_ROUNDS || "10", 10) || 10
const MIN_PASSWORD_LENGTH = 8

const documents = new Map()
const mongoState = {
    client: null,
    db: null,
    users: null,
    ready: null,
}

const createDocument = () => ({
    data: "",
    nextGuestNumber: 1,
    users: new Map(),
})

const getDocument = (documentID) => {
    if (!documents.has(documentID)) {
        documents.set(documentID, createDocument())
    }
    return documents.get(documentID)
}

const toUserList = (document) => {
    return Array.from(document.users.values()).map((user) => ({
        id: user.id,
        name: user.name,
        displayName: user.name || `Guest ${user.guestNumber}`,
    }))
}

const normalizeUsername = (username) => {
    if (typeof username !== "string") return null
    const trimmed = username.trim()
    if (!trimmed) return null
    return trimmed.slice(0, 32)
}

const normalizeUsernameKey = (username) => {
    const normalized = normalizeUsername(username)
    return normalized ? normalized.toLowerCase() : null
}

const validatePassword = (password) => {
    if (typeof password !== "string") return null
    if (password.length < MIN_PASSWORD_LENGTH || password.length > 128) return null
    return password
}

const issueToken = ({ username, userId, isGuest }) => {
    if (!username) return ""
    return jwt.sign(
        { username, sub: userId || null, guest: Boolean(isGuest) },
        JWT_SECRET,
        { expiresIn: "30d" }
    )
}

const emitAuthToken = (socket, { token, username, userId }) => {
    socket.emit("auth-token", {
        token: token || "",
        username: username || "",
        userId: userId || null,
    })
}

const connectMongo = async () => {
    if (mongoState.ready) return mongoState.ready

    mongoState.ready = MongoClient.connect(MONGODB_URI)
        .then((client) => {
            mongoState.client = client
            mongoState.db = client.db(MONGODB_DB)
            mongoState.users = mongoState.db.collection("users")
            return mongoState.users.createIndex(
                { usernameLower: 1 },
                { unique: true }
            )
        })
        .then(() => mongoState)
        .catch((error) => {
            mongoState.ready = null
            console.error("MongoDB connection failed:", error.message)
            throw error
        })

    return mongoState.ready
}

const getUsersCollection = async () => {
    const { users } = await connectMongo()
    return users
}

const removeUserFromDocument = (documentID, socketId) => {
    if (!documentID) return
    const document = documents.get(documentID)
    if (!document) return

    document.users.delete(socketId)
    io.to(documentID).emit("document-users", toUserList(document))

    if (document.users.size === 0) {
        documents.delete(documentID)
    }
}

const syncUserFromSocket = (socket) => {
    const documentID = socket.data.documentID
    if (!documentID) return
    const document = documents.get(documentID)
    if (!document) return
    const user = document.users.get(socket.id)
    if (!user) return

    user.name = socket.data.username || null
    io.to(documentID).emit("document-users", toUserList(document))
}

io.use((socket, next) => {
    const auth = socket.handshake.auth || {}
    if (typeof auth.token !== "string" || !auth.token) return next()

    try {
        const payload = jwt.verify(auth.token, JWT_SECRET)
        socket.data.username = normalizeUsername(payload.username)
        socket.data.userId =
            payload && typeof payload.sub === "string" && ObjectId.isValid(payload.sub)
                ? payload.sub
                : null
        socket.data.authToken = auth.token
    } catch (error) {
        socket.data.username = null
        socket.data.userId = null
        socket.data.authToken = null
    }

    return next()
})

io.on("connection", socket => {
    const incomingToken = socket.handshake.auth && socket.handshake.auth.token
    if (typeof incomingToken === "string" && incomingToken) {
        emitAuthToken(socket, {
            token: socket.data.authToken,
            username: socket.data.username,
            userId: socket.data.userId,
        })
    }

    socket.on("auth-register", async (payload = {}) => {
        const username = normalizeUsername(payload.username)
        const password = validatePassword(payload.password)

        if (!username || !password) {
            socket.emit("auth-error", { message: "Username and password required." })
            return
        }

        let users
        try {
            users = await getUsersCollection()
        } catch (error) {
            socket.emit("auth-error", { message: "Database unavailable." })
            return
        }

        const usernameLower = normalizeUsernameKey(username)
        try {
            const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS)
            const result = await users.insertOne({
                username,
                usernameLower,
                passwordHash,
                createdAt: new Date(),
            })
            const userId = result.insertedId.toString()
            const token = issueToken({ username, userId })
            socket.data.username = username
            socket.data.userId = userId
            socket.data.authToken = token
            syncUserFromSocket(socket)
            emitAuthToken(socket, { token, username, userId })
        } catch (error) {
            if (error && error.code === 11000) {
                socket.emit("auth-error", { message: "Username already exists." })
                return
            }
            console.error("Auth register failed:", error)
            socket.emit("auth-error", { message: "Registration failed." })
        }
    })

    socket.on("auth-login", async (payload = {}) => {
        const username = normalizeUsername(payload.username)
        const password = validatePassword(payload.password)

        if (!username || !password) {
            socket.emit("auth-error", { message: "Username and password required." })
            return
        }

        let users
        try {
            users = await getUsersCollection()
        } catch (error) {
            socket.emit("auth-error", { message: "Database unavailable." })
            return
        }

        try {
            const user = await users.findOne({
                usernameLower: normalizeUsernameKey(username),
            })
            if (!user) {
                socket.emit("auth-error", { message: "Invalid username or password." })
                return
            }

            const passwordMatches = await bcrypt.compare(password, user.passwordHash)
            if (!passwordMatches) {
                socket.emit("auth-error", { message: "Invalid username or password." })
                return
            }

            await users.updateOne(
                { _id: user._id },
                { $set: { lastLoginAt: new Date() } }
            )

            const userId = user._id.toString()
            const token = issueToken({ username: user.username, userId })
            socket.data.username = user.username
            socket.data.userId = userId
            socket.data.authToken = token
            syncUserFromSocket(socket)
            emitAuthToken(socket, { token, username: user.username, userId })
        } catch (error) {
            console.error("Auth login failed:", error)
            socket.emit("auth-error", { message: "Login failed." })
        }
    })

    socket.on("auth-logout", () => {
        socket.data.username = null
        socket.data.userId = null
        socket.data.authToken = null
        syncUserFromSocket(socket)
        emitAuthToken(socket, { token: "", username: "", userId: null })
    })

    socket.on("auth-status", () => {
        emitAuthToken(socket, {
            token: socket.data.authToken,
            username: socket.data.username,
            userId: socket.data.userId,
        })
    })

    socket.on("get-document", documentID => {
        const previousDocumentID = socket.data.documentID
        if (previousDocumentID && previousDocumentID !== documentID) {
            removeUserFromDocument(previousDocumentID, socket.id)
            socket.leave(previousDocumentID)
        }

        socket.data.documentID = documentID
        const document = getDocument(documentID)

        if (!document.users.has(socket.id)) {
            document.users.set(socket.id, {
                id: socket.id,
                name: socket.data.username || null,
                guestNumber: document.nextGuestNumber++,
            })
        } else {
            const existingUser = document.users.get(socket.id)
            existingUser.name = socket.data.username || existingUser.name
        }

        socket.join(documentID)
        socket.emit("load-document", document.data)
        io.to(documentID).emit("document-users", toUserList(document))
    })

    socket.on("send-changes", delta => {
        const documentID = socket.data.documentID
        if (!documentID) return
        socket.broadcast.to(documentID).emit("receive-changes", delta)
    })

    socket.on("set-username", username => {
        if (socket.data.userId) {
            socket.emit("auth-error", { message: "Log out to change your guest name." })
            return
        }
        const documentID = socket.data.documentID
        if (!documentID) return
        const document = documents.get(documentID)
        if (!document) return
        const user = document.users.get(socket.id)
        if (!user) return

        user.name = normalizeUsername(username)
        socket.data.username = user.name
        io.to(documentID).emit("document-users", toUserList(document))
        const token = issueToken({ username: user.name, isGuest: true })
        socket.data.authToken = token
        emitAuthToken(socket, {
            token,
            username: user.name,
            userId: null,
        })
    })

    socket.on("leave-document", documentID => {
        const activeDocumentID = socket.data.documentID
        const targetDocumentID = documentID || activeDocumentID
        if (!targetDocumentID) return

        removeUserFromDocument(targetDocumentID, socket.id)

        if (activeDocumentID === targetDocumentID) {
            socket.data.documentID = null
        }
        socket.leave(targetDocumentID)
    })

    socket.on("disconnect", () => {
        removeUserFromDocument(socket.data.documentID, socket.id)
    })
})
