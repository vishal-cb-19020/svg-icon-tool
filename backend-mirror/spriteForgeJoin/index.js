"use strict";

// ===================================
// SVG Sprite Service — Complete Serverless Code
// Fully server-based (NO localStorage dependency)
// ===================================
//
// SETUP REQUIRED:
// -----------------------------------------------
// 1. Go to Catalyst Console → Data Store
// 2. Create a new table called: SpriteRegistry
// 3. Add these columns:
//    ┌──────────────┬──────────┬────────────┐
//    │ Column Name  │ Type     │ Required   │
//    ├──────────────┼──────────┼────────────┤
//    │ sprite_name  │ TEXT     │ Yes        │
//    │ file_id      │ TEXT     │ Yes        │
//    │ file_name    │ TEXT     │ No         │
//    └──────────────┴──────────┴────────────┘
//    (ROWID, CREATEDTIME, MODIFIEDTIME are auto-created)
//
// 4. Go to Settings → Permission → Add this function
//    to the allowed roles for Data Store access.
//
// 5. Ensure File Store folder exists:
//    FOLDER_ID = "32235000000015888"
// -----------------------------------------------

const express = require("express");
const catalyst = require("zcatalyst-sdk-node");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();
app.use(express.json({ limit: "10mb" }));

app.use((req, res, next) => {
    res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type,x-session-id");
    if (req.method === "OPTIONS") {
        return res.status(204).end();
    }
    next();
});

const FOLDER_ID = "37672000000012906";
const TABLE_NAME = "SpriteForgeRegistry";

const ZOHO_ACCOUNTS_BASE = "https://accounts.zoho.in";
const ZOHO_AUTH_URL = `${ZOHO_ACCOUNTS_BASE}/oauth/v2/auth`;
const ZOHO_TOKEN_URL = `${ZOHO_ACCOUNTS_BASE}/oauth/v2/token`;
const ZOHO_USERINFO_URL = `${ZOHO_ACCOUNTS_BASE}/oauth/v2/userinfo`;
const ZOHO_FALLBACK_AVATAR_URL = `${ZOHO_ACCOUNTS_BASE}/oauth/user/photo`;

const ZOHO_CLIENT_ID = process.env.ZOHO_CLIENT_ID || "";
const ZOHO_CLIENT_SECRET = process.env.ZOHO_CLIENT_SECRET || "";
const ZOHO_REDIRECT_URI = process.env.ZOHO_REDIRECT_URI || "";
const ZOHO_SCOPE = process.env.ZOHO_SCOPE || "openid,email,profile,phone";

const AUTH_ENFORCE = String(process.env.AUTH_ENFORCE || "false").toLowerCase() === "true";
const SESSION_TTL_MS = Number(process.env.SESSION_TTL_MS || 24 * 60 * 60 * 1000);
const AVATAR_MAX_BYTES = Number(process.env.AVATAR_MAX_BYTES || 2 * 1024 * 1024);
const ALLOWED_AVATAR_HOST_REGEX = /(^|\.)zoho\.in$/i;

const sessions = new Map();

function decodeJwtPayload(token) {
    if (!token || token.split(".").length < 2) return null;
    try {
        const payload = token.split(".")[1];
        const normalized = payload.replace(/-/g, "+").replace(/_/g, "/");
        const json = Buffer.from(normalized, "base64").toString("utf8");
        return JSON.parse(json);
    } catch (error) {
        console.warn("id_token decode failed:", error.message);
        return null;
    }
}

function createSession(payload) {
    const sessionId = crypto.randomUUID();
    sessions.set(sessionId, {
        ...payload,
        createdAt: Date.now(),
        lastSeen: Date.now()
    });
    return sessionId;
}

function getSession(req) {
    const headerSessionId = req.headers["x-session-id"];
    const querySessionId = req.query && typeof req.query.session_id === "string"
        ? req.query.session_id
        : "";
    const sessionId = headerSessionId || querySessionId;
    if (!sessionId || typeof sessionId !== "string") return null;

    const session = sessions.get(sessionId);
    if (!session) return null;

    if (Date.now() - session.createdAt > SESSION_TTL_MS) {
        sessions.delete(sessionId);
        return null;
    }

    session.lastSeen = Date.now();
    return { sessionId, session };
}

function requireSession(req, res, next) {
    const current = getSession(req);
    if (!current) {
        return res.status(401).json({
            success: false,
            message: "Unauthorized. Missing or invalid session."
        });
    }
    req.auth = current;
    next();
}

async function fetchJson(url, options) {
    const response = await fetch(url, options);
    const text = await response.text();
    let json;
    try {
        json = text ? JSON.parse(text) : {};
    } catch {
        json = { raw: text };
    }
    return { response, json, text };
}

async function fetchAvatarDataUri(accessToken, primaryUrl) {
    const candidates = [];
    if (primaryUrl) candidates.push(primaryUrl);
    candidates.push(ZOHO_FALLBACK_AVATAR_URL);

    for (const url of candidates) {
        try {
            const parsed = new URL(url);
            if (parsed.protocol !== "https:" || !ALLOWED_AVATAR_HOST_REGEX.test(parsed.hostname)) {
                continue;
            }

            const resp = await fetch(parsed.toString(), {
                headers: { Authorization: `Bearer ${accessToken}` }
            });

            if (!resp.ok) continue;

            const contentType = (resp.headers.get("content-type") || "").toLowerCase();
            if (!contentType.startsWith("image/")) continue;

            const buffer = Buffer.from(await resp.arrayBuffer());
            if (!buffer.length || buffer.length > AVATAR_MAX_BYTES) continue;

            return {
                dataUri: `data:${contentType};base64,${buffer.toString("base64")}`,
                hash: crypto.createHash("sha256").update(buffer).digest("hex"),
                contentType,
                byteLength: buffer.length
            };
        } catch (error) {
            console.warn("Avatar fetch failed:", error.message);
        }
    }

    return null;
}

function isProtectedPath(pathname) {
    return pathname === "/save-sprite"
        || pathname.startsWith("/check-sprite/")
        || pathname.startsWith("/find-sprite/")
        || pathname === "/list-sprites"
        || pathname.startsWith("/get-sprite/")
        || pathname.startsWith("/sprite/")
        || pathname.startsWith("/delete-sprite/");
}

app.use((req, res, next) => {
    if (!AUTH_ENFORCE) return next();
    if (!isProtectedPath(req.path)) return next();
    return requireSession(req, res, next);
});

setInterval(() => {
    const now = Date.now();
    for (const [sessionId, session] of sessions.entries()) {
        if (now - session.createdAt > SESSION_TTL_MS) {
            sessions.delete(sessionId);
        }
    }
}, 60 * 60 * 1000).unref();

// ===================================
// AUTH: Build Zoho Login URL
// ===================================
app.get("/api/auth/zoho/url", (req, res) => {
    if (!ZOHO_CLIENT_ID || !ZOHO_REDIRECT_URI) {
        return res.status(500).json({
            success: false,
            message: "Missing ZOHO_CLIENT_ID or ZOHO_REDIRECT_URI"
        });
    }

    const authUrl = new URL(ZOHO_AUTH_URL);
    authUrl.searchParams.set("response_type", "code");
    authUrl.searchParams.set("client_id", ZOHO_CLIENT_ID);
    authUrl.searchParams.set("scope", ZOHO_SCOPE);
    authUrl.searchParams.set("redirect_uri", ZOHO_REDIRECT_URI);
    authUrl.searchParams.set("access_type", "offline");

    res.status(200).json({ success: true, url: authUrl.toString() });
});

// ===================================
// AUTH: Exchange code and create session
// ===================================
app.post("/api/auth/zoho/callback", async (req, res) => {
    try {
        const { code } = req.body || {};
        if (!code) {
            return res.status(400).json({ success: false, message: "Missing authorization code" });
        }

        if (!ZOHO_CLIENT_ID || !ZOHO_CLIENT_SECRET || !ZOHO_REDIRECT_URI) {
            return res.status(500).json({
                success: false,
                message: "Missing Zoho OAuth configuration"
            });
        }

        const form = new URLSearchParams({
            grant_type: "authorization_code",
            client_id: ZOHO_CLIENT_ID,
            client_secret: ZOHO_CLIENT_SECRET,
            redirect_uri: ZOHO_REDIRECT_URI,
            code
        });

        const tokenData = await fetchJson(ZOHO_TOKEN_URL, {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: form
        });

        if (!tokenData.response.ok || !tokenData.json.access_token) {
            return res.status(400).json({
                success: false,
                message: "Token exchange failed",
                details: tokenData.json
            });
        }

        const accessToken = tokenData.json.access_token;
        const idTokenPayload = decodeJwtPayload(tokenData.json.id_token);

        const userInfoData = await fetchJson(ZOHO_USERINFO_URL, {
            method: "GET",
            headers: { Authorization: `Bearer ${accessToken}` }
        });

        const userInfo = userInfoData.response.ok ? userInfoData.json : {};

        const mergedProfile = {
            ...idTokenPayload,
            ...userInfo
        };

        const userId = mergedProfile.sub || mergedProfile.user_id || mergedProfile.email;
        const avatarCandidate = mergedProfile.picture || mergedProfile.profile_picture;
        const avatar = await fetchAvatarDataUri(accessToken, avatarCandidate);

        const user = {
            id: userId || null,
            email: mergedProfile.email || null,
            name: mergedProfile.name || mergedProfile.given_name || mergedProfile.email || "Zoho User",
            picture: avatarCandidate || null,
            avatar: avatar ? avatar.dataUri : null,
            avatarHash: avatar ? avatar.hash : null
        };

        const sessionId = createSession({
            user,
            zohoProfile: mergedProfile,
            accessToken,
            refreshToken: tokenData.json.refresh_token || null
        });

        res.status(200).json({
            success: true,
            sessionId,
            user,
            zohoProfile: mergedProfile
        });
    } catch (error) {
        console.error("ZOHO CALLBACK ERROR:", error);
        res.status(500).json({ success: false, message: error.message || "OAuth callback failed" });
    }
});

// ===================================
// AUTH: Validate session
// ===================================
app.get("/api/auth/session", (req, res) => {
    const current = getSession(req);
    if (!current) {
        return res.status(401).json({ success: false, message: "Invalid session" });
    }

    res.status(200).json({
        success: true,
        sessionId: current.sessionId,
        user: current.session.user,
        zohoProfile: current.session.zohoProfile
    });
});

// ===================================
// AUTH: Logout
// ===================================
app.post("/api/auth/logout", (req, res) => {
    const sessionId = req.headers["x-session-id"];
    if (sessionId && typeof sessionId === "string") {
        sessions.delete(sessionId);
    }
    res.status(200).json({ success: true, message: "Logged out" });
});

// ===================================
// Optional avatar proxy (allowlisted)
// ===================================
app.get("/api/avatar/proxy", async (req, res) => {
    try {
        const encoded = req.query.url;
        if (!encoded || typeof encoded !== "string") {
            return res.status(400).json({ success: false, message: "Missing url query param" });
        }

        const targetUrl = Buffer.from(encoded, "base64").toString("utf8");
        const parsed = new URL(targetUrl);
        if (parsed.protocol !== "https:" || !ALLOWED_AVATAR_HOST_REGEX.test(parsed.hostname)) {
            return res.status(400).json({ success: false, message: "Avatar URL not allowed" });
        }

        const response = await fetch(parsed.toString());
        if (!response.ok) {
            return res.status(400).json({ success: false, message: "Failed to fetch avatar" });
        }

        const contentType = (response.headers.get("content-type") || "").toLowerCase();
        if (!contentType.startsWith("image/")) {
            return res.status(400).json({ success: false, message: "Invalid avatar content type" });
        }

        const buffer = Buffer.from(await response.arrayBuffer());
        if (buffer.length > AVATAR_MAX_BYTES) {
            return res.status(400).json({ success: false, message: "Avatar too large" });
        }

        res.setHeader("Content-Type", contentType);
        res.setHeader("Cache-Control", "public, max-age=300");
        res.status(200).send(buffer);
    } catch (error) {
        console.error("AVATAR PROXY ERROR:", error);
        res.status(500).json({ success: false, message: "Avatar proxy failed" });
    }
});

// ===================================
// HEALTH CHECK
// ===================================
app.all("/", (req, res) => {
    res.status(200).send("SVG Sprite Service is Live. Endpoints: POST /save-sprite, GET /sprite/:name, GET /find-sprite/:name, GET /get-sprite/:fileId, GET /list-sprites, DELETE /delete-sprite/:name");
});

// ===================================
// CHECK IF SPRITE EXISTS BY NAME
// ===================================
app.get("/check-sprite/:name", async (req, res) => {
    try {
        const catalystApp = catalyst.initialize(req);
        const zcql = catalystApp.zcql();
        const name = decodeURIComponent(req.params.name).replace(/'/g, "''");

        const result = await zcql.executeZCQLQuery(
            `SELECT sprite_name, file_id, CREATEDTIME FROM ${TABLE_NAME} WHERE sprite_name = '${name}'`
        );

        if (result && result.length > 0) {
            res.status(200).json({ exists: true, sprite: result[0][TABLE_NAME] });
        } else {
            res.status(200).json({ exists: false });
        }
    } catch (error) {
        console.error("CHECK ERROR:", error);
        res.status(500).json({ exists: false, message: error.message });
    }
});

// ===================================
// SAVE SVG SPRITE
// Uploads to File Store + registers name→fileId in Data Store
// Accepts optional `mode` in body: "replace" (default) or "new"
// ===================================
app.post("/save-sprite", async (req, res) => {
    try {
        const catalystApp = catalyst.initialize(req);
        const folder = catalystApp.filestore().folder(FOLDER_ID);
        const table = catalystApp.datastore().table(TABLE_NAME);
        const zcql = catalystApp.zcql();

        const { spriteName, svgContent, mode } = req.body;

        if (!spriteName || !svgContent) {
            return res.status(400).json({
                success: false,
                message: "Missing spriteName or svgContent"
            });
        }

        const saveMode = mode || "replace"; // "replace" or "new"

        // Check for existing sprite
        const escapedName = spriteName.replace(/'/g, "''");
        const existing = await zcql.executeZCQLQuery(
            `SELECT ROWID, file_id FROM ${TABLE_NAME} WHERE sprite_name = '${escapedName}'`
        );

        // If mode is "new" and name exists, generate unique name
        let finalName = spriteName;
        if (saveMode === "new" && existing && existing.length > 0) {
            let counter = 1;
            let candidateName = `${spriteName}(${counter})`;
            let candidateEscaped = candidateName.replace(/'/g, "''");
            let check = await zcql.executeZCQLQuery(
                `SELECT ROWID FROM ${TABLE_NAME} WHERE sprite_name = '${candidateEscaped}'`
            );
            while (check && check.length > 0) {
                counter++;
                candidateName = `${spriteName}(${counter})`;
                candidateEscaped = candidateName.replace(/'/g, "''");
                check = await zcql.executeZCQLQuery(
                    `SELECT ROWID FROM ${TABLE_NAME} WHERE sprite_name = '${candidateEscaped}'`
                );
            }
            finalName = candidateName;
            console.log(`Mode=new: renamed "${spriteName}" → "${finalName}"`);
        }

        // Sanitize file name
        const safeName = finalName.replace(/[^a-zA-Z0-9-_()]/g, "_");
        const fileName = safeName.endsWith(".svg") ? safeName : `${safeName}.svg`;
        const filePath = path.join("/tmp", fileName);

        // Write SVG to temp file and upload
        fs.writeFileSync(filePath, svgContent);

        const uploadResult = await folder.uploadFile({
            code: fs.createReadStream(filePath),
            name: fileName
        });

        // Clean up temp file
        fs.unlinkSync(filePath);

        const fileId = String(uploadResult.id || uploadResult.file_id);
        console.log("Upload result — fileId:", fileId, "fileName:", fileName);

        // Check if this finalName already exists in Data Store (for replace mode)
        const finalEscaped = finalName.replace(/'/g, "''");
        const finalExisting = (saveMode === "new")
            ? [] // new mode already has a unique name
            : (existing || []);

        if (finalExisting.length > 0) {
            // Delete the OLD file from File Store to avoid orphans
            const oldFileId = finalExisting[0][TABLE_NAME].file_id;
            if (oldFileId) {
                try {
                    await folder.deleteFile(oldFileId);
                    console.log(`Deleted old file ${oldFileId} from File Store`);
                } catch (delErr) {
                    console.warn(`Could not delete old file ${oldFileId}:`, delErr.message);
                    // Continue anyway — the old file becomes orphaned but save still works
                }
            }

            // Update existing record with new fileId
            const rowId = finalExisting[0][TABLE_NAME].ROWID;
            await table.updateRow({
                ROWID: rowId,
                file_id: fileId,
                file_name: fileName
            });
            console.log(`Updated existing record ROWID=${rowId} for "${finalName}" (old file ${oldFileId} → new file ${fileId})`);
        } else {
            // Insert new record
            await table.insertRow({
                sprite_name: finalName,
                file_id: fileId,
                file_name: fileName
            });
            console.log(`Inserted new record for "${finalName}"`);
        }

        res.status(200).json({
            success: true,
            message: "Sprite saved successfully",
            fileId: fileId,
            fileName: fileName,
            spriteName: finalName
        });

    } catch (error) {
        console.error("SAVE ERROR:", error);
        res.status(500).json({
            success: false,
            message: error.message || "Error saving sprite"
        });
    }
});

// ===================================
// FIND SPRITE BY NAME
// Looks up fileId from Data Store by sprite name
// ===================================
app.get("/find-sprite/:name", async (req, res) => {
    try {
        const catalystApp = catalyst.initialize(req);
        const zcql = catalystApp.zcql();
        const name = decodeURIComponent(req.params.name);
        const escapedName = name.replace(/'/g, "''");

        console.log("Finding sprite by name:", name);

        const result = await zcql.executeZCQLQuery(
            `SELECT file_id, file_name, sprite_name, CREATEDTIME FROM ${TABLE_NAME} WHERE sprite_name = '${escapedName}'`
        );

        if (result && result.length > 0) {
            const row = result[0][TABLE_NAME];
            res.status(200).json({
                success: true,
                fileId: row.file_id,
                fileName: row.file_name,
                spriteName: row.sprite_name,
                createdAt: row.CREATEDTIME
            });
        } else {
            res.status(404).json({
                success: false,
                message: `Sprite "${name}" not found`
            });
        }

    } catch (error) {
        console.error("FIND ERROR:", error);
        res.status(500).json({
            success: false,
            message: error.message || "Error finding sprite"
        });
    }
});

// ===================================
// LIST ALL SPRITES
// Returns all saved sprite names with their fileIds
// ===================================
app.get("/list-sprites", async (req, res) => {
    try {
        const catalystApp = catalyst.initialize(req);
        const zcql = catalystApp.zcql();

        const result = await zcql.executeZCQLQuery(
            `SELECT sprite_name, file_id, file_name, CREATEDTIME FROM ${TABLE_NAME} ORDER BY CREATEDTIME DESC`
        );

        const sprites = (result || []).map(row => ({
            name: row[TABLE_NAME].sprite_name,
            fileId: row[TABLE_NAME].file_id,
            fileName: row[TABLE_NAME].file_name,
            createdAt: row[TABLE_NAME].CREATEDTIME
        }));

        console.log(`Found ${sprites.length} sprites`);

        res.status(200).json({
            success: true,
            count: sprites.length,
            sprites: sprites
        });

    } catch (error) {
        console.error("LIST ERROR:", error);
        res.status(500).json({
            success: false,
            message: error.message || "Error listing sprites"
        });
    }
});

// ===================================
// RETRIEVE SVG SPRITE BY FILE ID
// Downloads actual SVG from File Store
// ===================================
app.get("/get-sprite/:fileId", async (req, res) => {
    try {
        const catalystApp = catalyst.initialize(req);
        const folder = catalystApp.filestore().folder(FOLDER_ID);
        const fileId = req.params.fileId;

        console.log("Downloading file by ID:", fileId);

        const fileContent = await folder.downloadFile(fileId);

        res.setHeader("Content-Type", "image/svg+xml");
        res.setHeader("Content-Disposition", "inline");
        res.setHeader("Cache-Control", "public, max-age=86400"); // Cache for 24h

        if (Buffer.isBuffer(fileContent)) {
            res.status(200).send(fileContent);
        } else if (fileContent && typeof fileContent.pipe === "function") {
            fileContent.pipe(res);
        } else {
            res.status(200).send(fileContent);
        }

    } catch (error) {
        console.error("RETRIEVE ERROR:", error);
        if (!res.headersSent) {
            res.status(500).json({
                success: false,
                message: error.message || "Error retrieving sprite"
            });
        }
    }
});

// ===================================
// RETRIEVE SVG SPRITE BY NAME (single URL)
// Looks up name in Data Store → downloads from File Store
// This is the URL you share / use as background-image
// Usage: GET /sprite/icon1  or  GET /sprite/icon1.svg
// ===================================
app.get("/sprite/:name", async (req, res) => {
    try {
        const catalystApp = catalyst.initialize(req);
        const zcql = catalystApp.zcql();
        const folder = catalystApp.filestore().folder(FOLDER_ID);

        let name = decodeURIComponent(req.params.name);
        // Strip .svg extension if provided for lookup
        const lookupName = name.replace(/\.svg$/i, "");
        const escapedName = lookupName.replace(/'/g, "''");

        console.log("Sprite by name:", lookupName);
        console.log("ZCQL query:", `SELECT file_id FROM ${TABLE_NAME} WHERE sprite_name = '${escapedName}'`);

        // Look up fileId from Data Store
        const result = await zcql.executeZCQLQuery(
            `SELECT file_id FROM ${TABLE_NAME} WHERE sprite_name = '${escapedName}'`
        );

        console.log("ZCQL result:", JSON.stringify(result));

        if (!result || result.length === 0) {
            return res.status(404).json({
                success: false,
                message: `Sprite "${lookupName}" not found`
            });
        }

        const fileId = result[0][TABLE_NAME].file_id;
        console.log("Resolved fileId:", fileId, "type:", typeof fileId);

        // Download from File Store — pass as string (same as working /get-sprite endpoint)
        const fileContent = await folder.downloadFile(fileId);

        res.setHeader("Content-Type", "image/svg+xml");
        res.setHeader("Content-Disposition", "inline");
        res.setHeader("Cache-Control", "public, max-age=86400");

        if (Buffer.isBuffer(fileContent)) {
            res.status(200).send(fileContent);
        } else if (fileContent && typeof fileContent.pipe === "function") {
            fileContent.pipe(res);
        } else {
            res.status(200).send(fileContent);
        }

    } catch (error) {
        console.error("SPRITE BY NAME ERROR:", error.message, error.stack);
        if (!res.headersSent) {
            res.status(500).json({
                success: false,
                message: error.message || "Error retrieving sprite by name"
            });
        }
    }
});

// ===================================
// DELETE SPRITE BY NAME
// Removes from both File Store and Data Store
// ===================================
app.delete("/delete-sprite/:name", async (req, res) => {
    try {
        const catalystApp = catalyst.initialize(req);
        const zcql = catalystApp.zcql();
        const name = decodeURIComponent(req.params.name);
        const escapedName = name.replace(/'/g, "''");

        console.log("Deleting sprite:", name);

        // Find the record
        const result = await zcql.executeZCQLQuery(
            `SELECT ROWID, file_id FROM ${TABLE_NAME} WHERE sprite_name = '${escapedName}'`
        );

        if (!result || result.length === 0) {
            return res.status(404).json({
                success: false,
                message: `Sprite "${name}" not found`
            });
        }

        const row = result[0][TABLE_NAME];
        const fileId = row.file_id;
        const rowId = row.ROWID;

        // Delete from File Store
        try {
            await catalystApp.filestore().folder(FOLDER_ID).deleteFile(parseInt(fileId));
            console.log("File deleted from File Store:", fileId);
        } catch (e) {
            console.warn("File delete failed (may already be deleted):", e.message);
        }

        // Delete from Data Store
        const table = catalystApp.datastore().table(TABLE_NAME);
        await table.deleteRow(rowId);
        console.log("Record deleted from Data Store:", rowId);

        res.status(200).json({
            success: true,
            message: `Sprite "${name}" deleted successfully`
        });

    } catch (error) {
        console.error("DELETE ERROR:", error);
        res.status(500).json({
            success: false,
            message: error.message || "Error deleting sprite"
        });
    }
});

module.exports = app;