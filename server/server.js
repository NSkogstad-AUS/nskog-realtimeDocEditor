const jwt = require("jsonwebtoken")
const io = require("socket.io")(3001, {
    cors: {
        origin: 'http://localhost:3000',
        methods: ['GET', 'POST'],
    },
})

const JWT_SECRET = process.env.JWT_SECRET || "dev-secret"

const documents = new Map()

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

const issueToken = (username) => {
    if (!username) return null
    return jwt.sign({ username }, JWT_SECRET, { expiresIn: "30d" })
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

io.use((socket, next) => {
    const auth = socket.handshake.auth || {}
    if (typeof auth.token !== "string" || !auth.token) return next()

    try {
        const payload = jwt.verify(auth.token, JWT_SECRET)
        socket.data.username = normalizeUsername(payload.username)
    } catch (error) {
        socket.data.username = null
    }

    return next()
})

io.on("connection", socket => {
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
        const documentID = socket.data.documentID
        if (!documentID) return
        const document = documents.get(documentID)
        if (!document) return
        const user = document.users.get(socket.id)
        if (!user) return

        user.name = normalizeUsername(username)
        socket.data.username = user.name
        io.to(documentID).emit("document-users", toUserList(document))
        socket.emit("auth-token", {
            token: issueToken(user.name),
            username: user.name,
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
