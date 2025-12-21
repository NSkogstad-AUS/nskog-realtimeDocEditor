const io = require("socket.io")(3001, {
    cors: {
        origin: 'http://localhost:3000',
        methods: ['GET', 'POST'],
    },
})

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
                name: null,
                guestNumber: document.nextGuestNumber++,
            })
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
        io.to(documentID).emit("document-users", toUserList(document))
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
