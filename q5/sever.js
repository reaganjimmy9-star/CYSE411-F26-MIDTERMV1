// CYSE 411 Exam Application
// WARNING: This code contains security vulnerabilities.
// Students must repair the implementation.

const loadBtn = document.getElementById("loadBtn");
const saveBtn = document.getElementById("saveSession");
const loadSessionBtn = document.getElementById("loadSession");

loadBtn.addEventListener("click", loadProfile);
saveBtn.addEventListener("click", saveSession);
loadSessionBtn.addEventListener("click", loadSession);

let currentProfile = null;


/* -------------------------
   Load Profile
-------------------------- */

function loadProfile() {
    const text = document.getElementById("profileInput").value;
    let profile;

    // 1. Safe Parsing
    try {
        profile = JSON.parse(text);
    } catch (e) {
        alert("Invalid JSON format"); // Fail safely
        return;
    }

    // 2. Strict Type & Required Field Validation
    if (
        !profile ||
        typeof profile !== "object" ||
        Array.isArray(profile) ||
        typeof profile.username !== "string" ||
        !Array.isArray(profile.notifications)
    ) {
        alert("Invalid profile format");
        return;
    }

    // 3. Ignore Unexpected Fields (Sanitization)
    // We manually construct the object to ensure "extra" malicious fields are dropped.
    const sanitizedProfile = {
        username: profile.username,
        notifications: []
    };

    // 4. Validate individual array elements
    for (let item of profile.notifications) {
        if (typeof item !== "string") {
            alert("Invalid profile format");
            return;
        }
        sanitizedProfile.notifications.push(item);
    }

    // Assign the cleaned object, not the raw input
    currentProfile = sanitizedProfile;
    renderProfile(sanitizedProfile);
}

/* -------------------------
   Render Profile 
-------------------------- */

function renderProfile(profile) {
    // 1. Clear existing content
    // Clearing with "" is safe, as no untrusted data is being parsed here.
    const list = document.getElementById("notifications");
    list.innerHTML = ""; 

    // 2. Securely render the Username
    // FIX: Replaced .innerHTML with .textContent
    // This prevents XSS by treating the username as plain text.
    const usernameElement = document.getElementById("username");
    if (profile && profile.username) {
        usernameElement.textContent = profile.username;
    }

    // 3. Securely render Notifications
    // FIX: Replaced .innerHTML with .textContent inside the loop
    if (profile && Array.isArray(profile.notifications)) {
        profile.notifications.forEach(notification => {
            const li = document.createElement("li");
            
            // This ensures characters like < and > are displayed literally
            // and NOT parsed as HTML tags.
            li.textContent = notification;
            
            list.appendChild(li);
        });
    }
}

/* -------------------------
   Browser Storage
-------------------------- */

function saveSession() {
    // Check if there is actually data to save
    if (!currentProfile) {
        alert("No active session to save.");
        return;
    }

    try {
        // We only save the necessary, validated fields.
        // This avoids storing "extra" sensitive data if the object was polluted.
        const sessionData = {
            username: currentProfile.username,
            notifications: currentProfile.notifications
        };

        localStorage.setItem("profile", JSON.stringify(sessionData));
        alert("Session saved");
    } catch (e) {
        console.error("Failed to save to localStorage", e);
    }
}


function loadSession() {
    const stored = localStorage.getItem("profile");

    // 1. Check if storage is empty
    if (!stored) {
        return; 
    }

    try {
        // 2. Safe Parsing: Handle corrupted JSON strings in storage
        const profile = JSON.parse(stored);

        // 3. Re-Validate: Never trust data from storage without checking types
        if (
            !profile ||
            typeof profile !== "object" ||
            Array.isArray(profile) ||
            typeof profile.username !== "string" ||
            !Array.isArray(profile.notifications)
        ) {
            throw new Error("Stored session data is malformed or invalid.");
        }

        // 4. Sanitize: Re-construct the object to ignore unexpected fields
        const validatedProfile = {
            username: profile.username,
            notifications: profile.notifications.filter(n => typeof n === 'string')
        };

        for (let n of profile.notifications) {
            if (typeof n !== "string") {
                throw new Error("Stored session data is malformed or invalid.");
            }
            validatedProfile.notifications.push(n);
        }

        currentProfile = validatedProfile;
        renderProfile(validatedProfile);

    } catch (e) {
        // 5. Fail Safely: If storage is manipulated/corrupted, clear it and reset
        console.error("Session restoration failed:", e.message);
        localStorage.removeItem("profile"); 
        currentProfile = null;
        alert("Session corrupted and has been reset.");
    }
}
