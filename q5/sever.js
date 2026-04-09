//q5b with explanation
const express = require("express")
const sqlite3 = require("sqlite3").verbose()
const bodyParser = require("body-parser")

const app = express()
const db = new sqlite3.Database("portal.db")

// Middleware to parse incoming request bodies
// This allows the server to read username/password from form data or JSON
app.use(bodyParser.urlencoded({ extended: true }))
app.use(bodyParser.json())

db.serialize(() => {

    // Create the users table if it does not already exist
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password TEXT
        )
    `)

    // Check whether the table is empty
    db.get("SELECT COUNT(*) AS count FROM users", (err, row) => {

        if (row.count === 0) {

            // Insert default users using parameterized queries
            // These are already safe because they use ? placeholders
            db.run(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                ["admin", "admin123"]
            )

            db.run(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                ["employee", "password"]
            )
        }

    })

})


app.post("/login", (req, res) => {

    // Read the submitted username and password from the request body
    const username = req.body.username;
    const password = req.body.password;

    // SECURITY FIX:
    // Instead of building SQL with string concatenation,
    // use a parameterized query with placeholders.
    //
    // This keeps the SQL structure fixed and sends user input separately,
    // so the database treats username/password as plain data, not SQL code.
    const query = "SELECT * FROM users WHERE username = ? AND password = ?";

    console.log("\nExecuting secure parameterized query");

    // Pass the actual user input as bound parameters
    // This prevents SQL injection because even malicious input like
    // "' OR '1'='1' --" is treated as a literal string value
    db.get(query, [username, password], (err, row) => {

        if (err) {
            // If the database throws an error, return a server error response
            console.error(err);
            return res.status(500).send("Database error");
        }

        // If a matching row is found, the login succeeds
        if (row) {
            res.send("Login success");
        } else {
            // Otherwise, no matching user was found
            res.send("Login failed");
        }
    });
});


app.listen(3000, () => {
    console.log("Server running on http://localhost:3000")
})
