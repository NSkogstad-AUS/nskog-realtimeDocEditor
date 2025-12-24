const jwt = require("jsonwebtoken")
const bcrypt = require("bcryptjs")
const crypto = require("crypto")
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
const RESET_TOKEN_BYTES =
    Number.parseInt(process.env.RESET_TOKEN_BYTES || "32", 10) || 32
const RESET_TOKEN_TTL_MINUTES =
    Number.parseInt(process.env.RESET_TOKEN_TTL_MINUTES || "30", 10) || 30
const RESET_TOKEN_DELIVERY = process.env.RESET_TOKEN_DELIVERY || "socket"
const RESET_BASE_URL = process.env.RESET_BASE_URL || ""

const documents = new Map()
const mongoState = {
    client: null,
    db: null,
    users: null,
    resetTokens: null,
    documents: null,
    ready: null,
}

const createDocument = (data = { ops: [] }) => ({
    data,
    nextGuestNumber: 1,
    users: new Map(),
})

const getDocumentFromMemory = (documentID) => {
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
            mongoState.resetTokens =
                mongoState.db.collection("password_reset_tokens")
            mongoState.documents = mongoState.db.collection("documents")
            return Promise.all([
                mongoState.users.createIndex(
                    { usernameLower: 1 },
                    { unique: true }
                ),
                mongoState.resetTokens.createIndex(
                    { tokenHash: 1 },
                    { unique: true }
                ),
                mongoState.resetTokens.createIndex(
                    { expiresAt: 1 },
                    { expireAfterSeconds: 0 }
                ),
                mongoState.resetTokens.createIndex({ userId: 1 }),
                mongoState.documents.createIndex({ updatedAt: 1 }),
            ])
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

const getDocumentsCollection = async () => {
    const { documents: documentsCollection } = await connectMongo()
    return documentsCollection
}

const getResetTokensCollection = async () => {
    const { resetTokens } = await connectMongo()
    return resetTokens
}

const getUserById = async (users, userId) => {
    if (!userId || !ObjectId.isValid(userId)) return null
    return users.findOne({ _id: new ObjectId(userId) })
}

const hashResetToken = (token) => {
    return crypto.createHash("sha256").update(token).digest("hex")
}

const buildResetUrl = (token) => {
    if (!RESET_BASE_URL) return ""
    const separator = RESET_BASE_URL.includes("?") ? "&" : "?"
    return `${RESET_BASE_URL}${separator}token=${token}`
}

const createResetToken = () => {
    const token = crypto.randomBytes(RESET_TOKEN_BYTES).toString("hex")
    const tokenHash = hashResetToken(token)
    const expiresAt = new Date(Date.now() + RESET_TOKEN_TTL_MINUTES * 60 * 1000)
    return { token, tokenHash, expiresAt }
}

const loadDocument = async (documentID) => {
    if (documents.has(documentID)) {
        return documents.get(documentID)
    }

    let data = { ops: [] }
    try {
        const documentsCollection = await getDocumentsCollection()
        const stored = await documentsCollection.findOne({ _id: documentID })
        if (stored && stored.data) {
            data = stored.data
        }
    } catch (error) {
        console.error("Document load failed:", error)
    }

    const document = createDocument(data)
    documents.set(documentID, document)
    return document
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

    socket.on("auth-request-password-reset", async (payload = {}) => {
        const username = normalizeUsername(payload.username)
        if (!username) {
            socket.emit("auth-error", { message: "Username required." })
            return
        }

        let users
        let resetTokens
        try {
            users = await getUsersCollection()
            resetTokens = await getResetTokensCollection()
        } catch (error) {
            socket.emit("auth-error", { message: "Database unavailable." })
            return
        }

        try {
            const user = await users.findOne({
                usernameLower: normalizeUsernameKey(username),
            })

            if (!user) {
                socket.emit("auth-reset-requested", {
                    message: "If that account exists, a reset link was sent.",
                })
                return
            }

            let tokenData = null
            for (let attempt = 0; attempt < 3; attempt += 1) {
                const candidate = createResetToken()
                try {
                    await resetTokens.insertOne({
                        userId: user._id,
                        tokenHash: candidate.tokenHash,
                        createdAt: new Date(),
                        expiresAt: candidate.expiresAt,
                        usedAt: null,
                    })
                    tokenData = candidate
                    break
                } catch (error) {
                    if (error && error.code === 11000) {
                        continue
                    }
                    throw error
                }
            }

            if (!tokenData) {
                socket.emit("auth-error", {
                    message: "Reset token generation failed.",
                })
                return
            }

            if (RESET_TOKEN_DELIVERY === "log") {
                console.log(
                    `Password reset token for ${user.username}: ${tokenData.token}`
                )
            }

            const resetUrl = buildResetUrl(tokenData.token)
            const response = {
                message: "If that account exists, a reset link was sent.",
            }

            if (RESET_TOKEN_DELIVERY === "socket") {
                response.resetToken = tokenData.token
            }

            if (resetUrl) {
                response.resetUrl = resetUrl
            }

            socket.emit("auth-reset-requested", response)
        } catch (error) {
            console.error("Password reset request failed:", error)
            socket.emit("auth-error", { message: "Reset request failed." })
        }
    })

    socket.on("auth-reset-password", async (payload = {}) => {
        const rawToken =
            typeof payload.token === "string" ? payload.token.trim() : ""
        const newPassword = validatePassword(payload.newPassword)

        if (!rawToken || !newPassword) {
            socket.emit("auth-error", {
                message: "Reset token and new password required.",
            })
            return
        }

        let users
        let resetTokens
        try {
            users = await getUsersCollection()
            resetTokens = await getResetTokensCollection()
        } catch (error) {
            socket.emit("auth-error", { message: "Database unavailable." })
            return
        }

        try {
            const tokenHash = hashResetToken(rawToken)
            const resetDoc = await resetTokens.findOne({ tokenHash })
            const now = new Date()

            if (!resetDoc || resetDoc.usedAt || resetDoc.expiresAt <= now) {
                socket.emit("auth-error", {
                    message: "Reset token invalid or expired.",
                })
                return
            }

            const user = await users.findOne({ _id: resetDoc.userId })
            if (!user) {
                socket.emit("auth-error", { message: "Account not found." })
                return
            }

            const samePassword = await bcrypt.compare(
                newPassword,
                user.passwordHash
            )
            if (samePassword) {
                socket.emit("auth-error", {
                    message: "New password must be different.",
                })
                return
            }

            const passwordHash = await bcrypt.hash(newPassword, BCRYPT_ROUNDS)
            await users.updateOne(
                { _id: user._id },
                {
                    $set: {
                        passwordHash,
                        passwordUpdatedAt: new Date(),
                        lastPasswordResetAt: new Date(),
                    },
                }
            )
            await resetTokens.updateOne(
                { _id: resetDoc._id },
                { $set: { usedAt: new Date() } }
            )
            await resetTokens.deleteMany({
                userId: user._id,
                _id: { $ne: resetDoc._id },
            })

            const userId = user._id.toString()
            const token = issueToken({ username: user.username, userId })
            socket.data.username = user.username
            socket.data.userId = userId
            socket.data.authToken = token
            syncUserFromSocket(socket)
            emitAuthToken(socket, { token, username: user.username, userId })
            socket.emit("auth-success", { message: "Password reset." })
        } catch (error) {
            console.error("Password reset failed:", error)
            socket.emit("auth-error", { message: "Password reset failed." })
        }
    })

    socket.on("auth-change-password", async (payload = {}) => {
        if (!socket.data.userId) {
            socket.emit("auth-error", { message: "Login required." })
            return
        }

        const currentPassword = validatePassword(payload.currentPassword)
        const newPassword = validatePassword(payload.newPassword)
        if (!currentPassword || !newPassword) {
            socket.emit("auth-error", {
                message: "Current and new password required.",
            })
            return
        }

        if (currentPassword === newPassword) {
            socket.emit("auth-error", {
                message: "New password must be different.",
            })
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
            const user = await getUserById(users, socket.data.userId)
            if (!user) {
                socket.emit("auth-error", { message: "Account not found." })
                return
            }

            const passwordMatches = await bcrypt.compare(
                currentPassword,
                user.passwordHash
            )
            if (!passwordMatches) {
                socket.emit("auth-error", { message: "Invalid current password." })
                return
            }

            const newHash = await bcrypt.hash(newPassword, BCRYPT_ROUNDS)
            await users.updateOne(
                { _id: user._id },
                { $set: { passwordHash: newHash, passwordUpdatedAt: new Date() } }
            )
            socket.emit("auth-success", { message: "Password updated." })
        } catch (error) {
            console.error("Auth password change failed:", error)
            socket.emit("auth-error", { message: "Password update failed." })
        }
    })

    socket.on("auth-delete-account", async (payload = {}) => {
        if (!socket.data.userId) {
            socket.emit("auth-error", { message: "Login required." })
            return
        }

        const password = validatePassword(payload.password)
        if (!password) {
            socket.emit("auth-error", { message: "Password required." })
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
            const user = await getUserById(users, socket.data.userId)
            if (!user) {
                socket.emit("auth-error", { message: "Account not found." })
                return
            }

            const passwordMatches = await bcrypt.compare(password, user.passwordHash)
            if (!passwordMatches) {
                socket.emit("auth-error", { message: "Invalid password." })
                return
            }

            await users.deleteOne({ _id: user._id })
            socket.data.username = null
            socket.data.userId = null
            socket.data.authToken = null
            syncUserFromSocket(socket)
            emitAuthToken(socket, { token: "", username: "", userId: null })
            socket.emit("auth-success", { message: "Account deleted." })
        } catch (error) {
            console.error("Auth delete account failed:", error)
            socket.emit("auth-error", { message: "Account deletion failed." })
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

    socket.on("get-document", async (documentID) => {
        if (typeof documentID !== "string" || !documentID.trim()) return
        const previousDocumentID = socket.data.documentID
        if (previousDocumentID && previousDocumentID !== documentID) {
            removeUserFromDocument(previousDocumentID, socket.id)
            socket.leave(previousDocumentID)
        }

        socket.data.documentID = documentID
        const document = await loadDocument(documentID)

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

    socket.on("save-document", async (payload = {}) => {
        const documentID = socket.data.documentID
        if (!documentID) return
        if (!payload || typeof payload !== "object") return
        const data = payload.data
        if (!data) return

        const document = getDocumentFromMemory(documentID)
        document.data = data

        try {
            const documentsCollection = await getDocumentsCollection()
            await documentsCollection.updateOne(
                { _id: documentID },
                { $set: { data, updatedAt: new Date() } },
                { upsert: true }
            )
        } catch (error) {
            console.error("Document save failed:", error)
        }
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
