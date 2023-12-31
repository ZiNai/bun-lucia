import { consola } from "consola";
import { auth } from "./lucia";
import { LuciaError } from "lucia";
// import { lucia } from "lucia";

Bun.serve({
    async fetch(req) {
        const url = new URL(req.url);

        // pages router
        if (url.pathname === "/") {
            return new Response(Bun.file("pages/index.html"), {
                headers: {
                    "Content-Type": "text/html",
                },
            });
        }
        if (url.pathname === "/regsitry") {
            return new Response(Bun.file("pages/regsitry.html"), {
                headers: {
                    "Content-Type": "text/html",
                },
            });
        }
        if (url.pathname === "/logout") {
            return new Response(Bun.file("pages/logout.html"), {
                headers: {
                    "Content-Type": "text/html",
                },
            });
        }
        // actions router
        if (url.pathname === '/signout') {
            const authRequest = auth.handleRequest(req);
            // check if user is authenticated
            const session = await authRequest.validate(); // or `authRequest.validateBearerToken()`
            if (!session) {
                return new Response("Unauthorized", {
                    status: 401
                });
            }
            // make sure to invalidate the current session!
            await auth.invalidateSession(session.sessionId);

            // for session cookies
            // create blank session cookie
            const sessionCookie = auth.createSessionCookie(null);
            return new Response(null, {
                headers: {
                    Location: "/", // redirect to login page
                    "Set-Cookie": sessionCookie.serialize() // delete session cookie
                },
                status: 302
            });
        }


        if (url.pathname === '/signin') {
            const formData = await req.formData();
            const username = formData.get("username");
            const password = formData.get("password");
            // basic check
            if (
                typeof username !== "string" ||
                username.length < 1 ||
                username.length > 31
            ) {
                return new Response("Invalid username", {
                    status: 400
                });
            }
            if (
                typeof password !== "string" ||
                password.length < 1 ||
                password.length > 255
            ) {
                return new Response("Invalid password", {
                    status: 400
                });
            }
            try {
                // find user by key
                // and validate password
                const key = await auth.useKey("username", username.toLowerCase(), password);
                const session = await auth.createSession({
                    userId: key.userId,
                    attributes: {}
                });
                const sessionCookie = auth.createSessionCookie(session);
                return new Response(null, {
                    headers: {
                        Location: "/logout", // redirect to profile page
                        "Set-Cookie": sessionCookie.serialize() // store session cookie
                    },
                    status: 302
                });
            } catch (e) {
                if (
                    e instanceof LuciaError &&
                    (e.message === "AUTH_INVALID_KEY_ID" ||
                        e.message === "AUTH_INVALID_PASSWORD")
                ) {
                    // user does not exist
                    // or invalid password
                    return new Response("Incorrect username or password", {
                        status: 400
                    });
                }
                return new Response("An unknown error occurred", {
                    status: 500
                });
            }

        }
        // parse formdata at /action
        if (url.pathname === '/signup') {
            const formdata = await req.formData();
            // console.log(formdata);
            const username = formdata.get("username");
            const password = formdata.get("password");
            if (
                typeof username !== "string" ||
                username.length < 4 ||
                username.length > 31
            ) {
                return new Response("Invalid username", {
                    status: 400
                });
            }
            if (
                typeof password !== "string" ||
                password.length < 6 ||
                password.length > 255
            ) {
                return new Response("Invalid password", {
                    status: 400
                });
            }
            try {
                const user = await auth.createUser({
                    key: {
                        providerId: "username", // auth method
                        providerUserId: username.toLowerCase(), // unique id when using "username" auth method
                        password // hashed by Lucia
                    },
                    attributes: {
                        username
                    }
                });
                const session = await auth.createSession({
                    userId: user.userId,
                    attributes: {}
                });
                const sessionCookie = auth.createSessionCookie(session);
                // redirect to profile page
                return new Response(null, {
                    headers: {
                        Location: "/",
                        "Set-Cookie": sessionCookie.serialize() // store session cookie
                    },
                    status: 302
                });
            } catch (e: any) {
                consola.error(e)
                // console.log(e.name,e.code)
                // console.log(JSON.stringify(e))
                if (
                    e.code === 'P2002'
                ) {
                    return new Response("Username already taken", {
                        status: 400
                    });
                }
                // this part depends on the database you're using
                // check for unique constraint error in user table
                // consola.log(e?.message?.code)
                // if (
                //     e instanceof LuciaError.SomeDatabaseError &&
                //     e.message === USER_TABLE_UNIQUE_CONSTRAINT_ERROR
                // ) {
                //     return new Response("Username already taken", {
                //         status: 400
                //     });
                // }

                return new Response("An unknown error occurred", {
                    status: 500
                });
            }
        }

        return new Response("Not Found", { status: 404 });
    },
});
