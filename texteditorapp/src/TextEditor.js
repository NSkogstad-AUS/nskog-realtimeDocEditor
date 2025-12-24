import { useCallback, useEffect, useRef, useState } from "react"
import Quill from "quill"
import "quill/dist/quill.snow.css"
import { io } from 'socket.io-client'
import { useParams } from "react-router-dom"

const TOOLBAR_OPTIONS = [
    [{ header: [1, 2, 3, 4, 5, 6, false] }],
    [{ font: [] }],
    [{ list: "ordered" }, { list: "bullet" }],
    ["bold", "italic", "underline"],
    [{ color: [] }, { background: [] }],
    [{ script: "sub" }, { script: "super" }],
    [{ align: [] }], 
    ["image", "blockquote", "code-block"],
    ["clean"],
]

const AUTH_TOKEN_KEY = "doceditor.authToken"
const AUTH_USERNAME_KEY = "doceditor.username"
const MIN_PASSWORD_LENGTH = 8

export default function TextEditor() {
    const {id: documentID} = useParams()
    const [socket, setSocket] = useState()
    const [quill, setQuill] = useState()
    const [users, setUsers] = useState([])
    const [displayName, setDisplayName] = useState(() => localStorage.getItem(AUTH_USERNAME_KEY) || "")
    const [loginUsername, setLoginUsername] = useState(() => localStorage.getItem(AUTH_USERNAME_KEY) || "")
    const [loginPassword, setLoginPassword] = useState("")
    const [authUserId, setAuthUserId] = useState(null)
    const [authError, setAuthError] = useState("")
    const saveTimerRef = useRef(null)


    useEffect(() => {
        const s = io("http://localhost:3001", {
            auth: { token: localStorage.getItem(AUTH_TOKEN_KEY) || "" },
        })
        setSocket(s)

        return () => {
            s.disconnect()
        }
    }, [])

    useEffect(() => {
        if (socket == null || quill == null) return

        socket.once("load-document", document => {
            quill.setContents(document)
            quill.enable()
        })

        socket.emit("get-document", documentID)
    }, [socket, quill, documentID])

    useEffect(() => {
        if (socket == null) return

        return () => {
            socket.emit("leave-document", documentID)
        }
    }, [socket, documentID])

    useEffect(() => {
        if (socket == null) return

        const handler = (documentUsers) => {
            setUsers(documentUsers)
        }
        socket.on("document-users", handler)

        return () => {
            socket.off("document-users", handler)
        }
    }, [socket])

    useEffect(() => {
        if (socket == null) return

        const handler = (payload) => {
            const nextToken = payload && payload.token ? payload.token : ""
            const nextUsername = payload && payload.username ? payload.username : ""
            const nextUserId = payload && payload.userId ? payload.userId : null

            if (nextToken) {
                localStorage.setItem(AUTH_TOKEN_KEY, nextToken)
            } else {
                localStorage.removeItem(AUTH_TOKEN_KEY)
            }

            if (nextUsername) {
                localStorage.setItem(AUTH_USERNAME_KEY, nextUsername)
            } else {
                localStorage.removeItem(AUTH_USERNAME_KEY)
            }

            setDisplayName(nextUsername)
            setLoginUsername(nextUsername)
            setLoginPassword("")
            setAuthUserId(nextUserId)
            setAuthError("")
        }

        socket.on("auth-token", handler)
        socket.emit("auth-status")

        return () => {
            socket.off("auth-token", handler)
        }
    }, [socket])

    useEffect(() => {
        if (socket == null) return

        const handler = (payload) => {
            const message =
                payload && payload.message ? payload.message : "Authentication failed."
            setAuthError(message)
        }

        socket.on("auth-error", handler)

        return () => {
            socket.off("auth-error", handler)
        }
    }, [socket])

    useEffect(() => {
        if (socket == null || quill == null) return

        const handler = (delta) => {
            quill.updateContents(delta)
        }
        socket.on('receive-changes', handler)

        return () => {
            socket.off('receive-changes', handler)
        }
    }, [socket, quill])

    useEffect(() => {
        if (socket == null || quill == null) return

        const handler = (delta, oldDelta, source) => {
            if (source !== 'user') return
            socket.emit('send-changes', delta)

            if (saveTimerRef.current) {
                clearTimeout(saveTimerRef.current)
            }

            saveTimerRef.current = setTimeout(() => {
                socket.emit("save-document", {
                    data: quill.getContents(),
                })
            }, 800)
        }

        quill.on('text-change', handler)

        return () => {
            quill.off('text-change', handler)
            if (saveTimerRef.current) {
                clearTimeout(saveTimerRef.current)
                saveTimerRef.current = null
            }
        }
    }, [socket, quill])

    const handleUsernameSubmit = useCallback((event) => {
        event.preventDefault()
        if (socket == null) return

        const trimmed = displayName.trim()
        socket.emit("set-username", trimmed)
        setDisplayName(trimmed)
    }, [socket, displayName])

    const handleLoginSubmit = useCallback((event) => {
        event.preventDefault()
        if (socket == null) return
        setAuthError("")

        const trimmed = loginUsername.trim()
        socket.emit("auth-login", { username: trimmed, password: loginPassword })
    }, [socket, loginUsername, loginPassword])

    const handleRegister = useCallback((event) => {
        event.preventDefault()
        if (socket == null) return
        setAuthError("")

        const trimmed = loginUsername.trim()
        socket.emit("auth-register", { username: trimmed, password: loginPassword })
    }, [socket, loginUsername, loginPassword])

    const handleLogout = useCallback(() => {
        if (socket == null) return
        setAuthError("")
        socket.emit("auth-logout")
    }, [socket])

    const wrapperRef = useCallback((wrapper) => {
        if (wrapper == null) return

        wrapper.innerHTML = ""
        const editor = document.createElement("div")
        wrapper.append(editor)

        const q = new Quill(editor, {
            theme: "snow", 
            modules: {toolbar: TOOLBAR_OPTIONS}
        })

        q.disable()
        q.setText('Loading...')

        setQuill(q)
    }, [])
    const socketId = socket && socket.id
    const isAuthenticated = Boolean(authUserId)
    const authReady =
        socket != null &&
        loginUsername.trim().length > 0 &&
        loginPassword.length >= MIN_PASSWORD_LENGTH

    return (
        <div className="editor-shell">
            <div className="user-bar">
                <div className="user-controls">
                    <form className="user-form" onSubmit={handleUsernameSubmit}>
                        <label className="user-label" htmlFor="username-input">Name</label>
                        <input
                            id="username-input"
                            type="text"
                            value={displayName}
                            onChange={(event) => setDisplayName(event.target.value)}
                            placeholder="Guest name (optional)"
                            maxLength={32}
                            disabled={socket == null || isAuthenticated}
                        />
                        <button
                            type="submit"
                            disabled={socket == null || isAuthenticated}
                        >
                            Set
                        </button>
                    </form>
                    <form className="auth-form" onSubmit={handleLoginSubmit}>
                        <label className="user-label" htmlFor="login-username">Login</label>
                        <input
                            id="login-username"
                            type="text"
                            value={loginUsername}
                            onChange={(event) => setLoginUsername(event.target.value)}
                            placeholder="Username"
                            maxLength={32}
                            autoComplete="username"
                            disabled={socket == null || isAuthenticated}
                        />
                        <label className="user-label" htmlFor="login-password">Password</label>
                        <input
                            id="login-password"
                            type="password"
                            value={loginPassword}
                            onChange={(event) => setLoginPassword(event.target.value)}
                            placeholder="Password"
                            minLength={MIN_PASSWORD_LENGTH}
                            maxLength={128}
                            autoComplete="current-password"
                            disabled={socket == null || isAuthenticated}
                        />
                        <div className="auth-actions">
                            <button
                                type="submit"
                                disabled={!authReady || isAuthenticated}
                            >
                                Log in
                            </button>
                            <button
                                type="button"
                                onClick={handleRegister}
                                disabled={!authReady || isAuthenticated}
                            >
                                Register
                            </button>
                            {isAuthenticated ? (
                                <button type="button" onClick={handleLogout}>
                                    Log out
                                </button>
                            ) : null}
                        </div>
                        {authError ? (
                            <span className="auth-error">{authError}</span>
                        ) : null}
                    </form>
                </div>
                <div className="user-list">
                    {users.length === 0 ? (
                        <span className="user-empty">No active users</span>
                    ) : (
                        users.map((user) => {
                            const isSelf = socketId && user.id === socketId
                            return (
                                <span
                                    key={user.id}
                                    className={`user-pill${isSelf ? " is-self" : ""}`}
                                >
                                    {user.displayName}{isSelf ? " (you)" : ""}
                                </span>
                            )
                        })
                    )}
                </div>
            </div>
            <div className="container" ref={wrapperRef}></div>
        </div>
    )
}
