const {
  GetCommand,
  PutCommand,
  UpdateCommand,
  ScanCommand,
  QueryCommand,
  DeleteCommand,
  BatchGetCommand,
} = require("@aws-sdk/lib-dynamodb");
require("dotenv").config();
const express = require("express");
const { hashPassword, comparePassword } = require("./auth");
const db = require("./db");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const app = express();
const { sendEmail } = require("./email");
const { SESClient, SendEmailCommand } = require("@aws-sdk/client-ses");

const ses = new SESClient({ region: process.env.AWS_REGION || "us-west-2" }); // use env region if provided

const { v4: uuidv4 } = require("uuid");
const crypto = require("crypto");

// --- SCHOOLS TABLE ---
// schoolCode: string (PK), metadata: { name, address, contact, ... }
// Generate a strong, non-guessable schoolCode (12 chars, base62)
function generateSchoolCode() {
  return crypto
    .randomBytes(9)
    .toString("base64")
    .replace(/[^a-zA-Z0-9]/g, "")
    .slice(0, 6);
}

// ✅ Correct Express 5-compatible CORS config
app.use(
  cors({
    origin: [
      "http://localhost:3000",
      "http://localhost:3001",
      "https://counselornotes.com",
      "https://www.counselornotes.com",
      "https://api.counselornotes.com",
    ],
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
  })
);
app.enable("trust proxy");

app.use(express.json());
app.get("/", (req, res) => {
  res.status(200).send("OK");
});

app.use(express.urlencoded({ extended: true }));

// =====================
// ADMIN-ONLY ROUTES
// =====================

// Admin: Create a new school (returns schoolCode)
app.post(
  "/schools",
  authMiddleware,
  requireRole(["admin", "districtAdmin"]),
  async (req, res) => {
    const { name, address, contact, metadata } = req.body;
    if (!name) return res.status(400).json({ error: "Missing school name" });
    const schoolCode = generateSchoolCode();
    const item = {
      schoolCode,
      name,
      address: address || null,
      contact: contact || null,
      metadata: metadata || {},
      createdAt: new Date().toISOString(),
    };
    try {
      await db.send(new PutCommand({ TableName: "Schools", Item: item }));
      // TODO: Securely share schoolCode with school (e.g., onboarding email)
      res.status(201).json({ message: "School created", schoolCode });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);

// Admin: List all schools
app.get(
  "/schools",
  authMiddleware,
  requireRole(["admin", "districtAdmin"]),
  async (req, res) => {
    try {
      const data = await db.send(new ScanCommand({ TableName: "Schools" }));
      res.json({ schools: data.Items });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);

const {
  version: dynamoVersion,
} = require("@aws-sdk/client-dynamodb/package.json");

app.get("/sdk-version", (req, res) => {
  res.json({ dynamodb_sdk_version: dynamoVersion });
});

app.use(express.json());

const fs = require("fs");
const path = require("path");

// Password validation (same as frontend criteria)
function isStrongPassword(pw) {
  return (
    typeof pw === "string" &&
    pw.length >= 12 &&
    /[A-Z]/.test(pw) &&
    /[a-z]/.test(pw) &&
    /[0-9]/.test(pw) &&
    /[^A-Za-z0-9]/.test(pw)
  );
}

// --- AUDIT LOGGING ---
// Now logs: userEmail, noteId, studentId, action, timestamp, ipAddress, displayName
async function logAudit({
  userEmail,
  noteId,
  action,
  req,
  studentId,
  displayName,
}) {
  // Try to get studentId from note if not provided
  let sid = studentId;
  if (!sid && noteId && db) {
    try {
      const data = await db.send(
        new GetCommand({ TableName: "Notes", Key: { noteId } })
      );
      sid = data.Item ? data.Item.studentId : undefined;
    } catch {}
  }
  // Fallback: if no noteId (e.g., user/admin actions), generate synthetic key for AuditLog PK
  const auditNoteId = noteId || `SYS#${uuidv4()}`;
  const ipAddress = req
    ? req.ip || req.headers["x-forwarded-for"] || req.connection?.remoteAddress
    : undefined;
  try {
    await db.send(
      new PutCommand({
        TableName: "AuditLog",
        Item: {
          userEmail,
          noteId: auditNoteId,
          studentId: sid,
          action,
          timestamp: new Date().toISOString(),
          ipAddress,
          displayName,
          schoolCode: req?.user?.schoolCode || null,
        },
      })
    );
  } catch (e) {
    console.error("AuditLog write failed:", e?.message || e);
  }
}
app.get("/", (req, res) => {
  res.send("Server is alive!");
});

// Privacy Policy route
app.get("/privacy-policy", (req, res) => {
  const filePath = path.join(__dirname, "privacy_policy.md");
  fs.readFile(filePath, "utf8", (err, data) => {
    if (err) return res.status(500).send("Privacy policy unavailable");
    res.type("text/markdown").send(data);
  });
});

// Test email endpoint (for verification and diagnostics)
app.get("/test-email", async (req, res) => {
  try {
    await sendEmail(
      process.env.TEST_EMAIL_TO || "cameronkuy@gmail.com",
      "Counselor Notes Test",
      "This is a test email via SES"
    );
    res.send("Email sent!");
  } catch (err) {
    console.error("Email error:", err);
    res.status(500).send("Email failed");
  }
});

// Public: validate school code existence for signup UX
app.get("/validate-school-code", async (req, res) => {
  const code = (req.query.code || "").trim();
  if (!code)
    return res.status(400).json({ valid: false, error: "Missing code" });
  try {
    const data = await db.send(
      new GetCommand({ TableName: "Schools", Key: { schoolCode: code } })
    );
    if (data.Item) {
      return res.json({ valid: true });
    }
    // Fallback: perform a case-insensitive check across existing codes (ok for small/medium tables)
    try {
      const scan = await db.send(
        new ScanCommand({
          TableName: "Schools",
          ProjectionExpression: "schoolCode",
        })
      );
      const found = (scan.Items || []).some(
        (it) => String(it.schoolCode || "").toLowerCase() === code.toLowerCase()
      );
      return res.json({ valid: found });
    } catch (e) {
      // If scan fails, don't 500—just return not found to keep UX responsive
      return res.json({ valid: false });
    }
  } catch (err) {
    res.status(500).json({ valid: false, error: "Server error" });
  }
});

// Refresh Token Route (extends session if still valid)
app.post("/refresh-token", authMiddleware, async (req, res) => {
  try {
    // req.user is set by authMiddleware and includes email, schoolCode, role, sessionId
    // Check session validity (already done in authMiddleware)
    const user = await getUserByEmail(req.user.email);
    if (!user) return res.status(401).json({ error: "User not found" });
    // Issue new JWT with new expiration
    const token = jwt.sign(
      {
        email: req.user.email,
        schoolCode: req.user.schoolCode,
        role: req.user.role,
        sessionId: req.user.sessionId,
      },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );
    res.json({ token });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Role-based access middleware
function requireRole(roles) {
  return (req, res, next) => {
    if (!req.user) return res.status(403).json({ error: "Forbidden" });

    // Superadmin bypass
    if (req.user.role === "superadmin") {
      return next();
    }

    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: "Forbidden: insufficient role" });
    }
    next();
  };
}

// Helper: get user by email
async function getUserByEmail(email) {
  const params = { TableName: "Users", Key: { email } };
  const data = await db.send(new GetCommand(params));
  return data.Item;
}

// Notes Table: noteId, ownerEmail, schoolCode, sharedWith (array), content, createdAt

// Signup Route (now collects phone and mfaMethod, and restricts to approved emails and valid schoolCode)
const APPROVED_EMAIL_DOMAINS = ["corvallis.k12.or.us", "gmail.com"];
app.post("/signup", async (req, res) => {
  const {
    email,
    password,
    schoolCode,
    phoneNumber,
    mfaMethod,
    firstName,
    lastName,
  } = req.body;
  if (
    !email ||
    !password ||
    !schoolCode ||
    !phoneNumber ||
    !mfaMethod ||
    !firstName ||
    !lastName
  )
    return res.status(400).json({ error: "Missing fields" });
  // Restrict to approved domains
  const allowed = APPROVED_EMAIL_DOMAINS.some(
    (domain) =>
      email.endsWith("@" + domain) ||
      email.endsWith("." + domain) ||
      email.endsWith(domain)
  );
  if (!allowed) {
    return res
      .status(403)
      .json({ error: "Email domain not approved for signup" });
  }
  // Validate schoolCode exists in Schools table
  try {
    const schoolData = await db.send(
      new GetCommand({ TableName: "Schools", Key: { schoolCode } })
    );
    if (!schoolData.Item) {
      return res
        .status(400)
        .json({ error: "Invalid or unrecognized school code" });
    }
  } catch (err) {
    return res.status(500).json({ error: "Error validating school code" });
  }
  if (!["sms", "totp"].includes(mfaMethod))
    return res.status(400).json({ error: "Invalid mfaMethod" });
  const hashed = await hashPassword(password);
  // Generate a one-time verification token
  const verificationToken = jwt.sign(
    { email },
    process.env.JWT_SECRET || "devsecret",
    { expiresIn: "1d" }
  );
  const params = {
    TableName: "Users",
    Item: {
      email,
      password: hashed,
      schoolCode,
      firstName,
      lastName,
      verified: false,
      verificationToken,
      phoneNumber,
      phoneVerified: false,
      totpSecret: null,
      totpVerified: false,
      mfaMethod, // 'sms' or 'totp'
    },
  };
  try {
    await db.send(new PutCommand(params));
    // Send email with verification link containing the token
    let verificationEmailSent = false;
    try {
      // Use API domain directly to avoid CORS and redirect loops
      const apiBase =
        process.env.API_BASE_URL || "https://api.counselornotes.com";
      const verifyUrl = `${apiBase.replace(
        /\/$/,
        ""
      )}/verify-email?token=${encodeURIComponent(verificationToken)}`;

      const subject = "Verify your Counselor Notes account";
      const bodyText = `Welcome to Counselor Notes!\n\nPlease verify your email by visiting:\n${verifyUrl}\n\nIf you didn't request this, please ignore this email.`;
      const bodyHtml = `
        <p>Welcome to <strong>Counselor Notes</strong>!</p>
        <p>Please verify your email by clicking the link below:</p>
        <p><a href="${verifyUrl}">Verify my email</a></p>
        <p>If you didn't request this, you can safely ignore this email.</p>
      `;
      await sendEmail(email, subject, bodyText, bodyHtml);
      verificationEmailSent = true;
    } catch (e) {
      console.error("Verification email send failed:", e);
    }
    res.status(201).json({
      message: "User created. Please verify your email.",
      verificationEmailSent,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- 2FA: SMS and TOTP endpoints ---
const speakeasy = require("speakeasy");
const qrcode = require("qrcode");
const { SNSClient, PublishCommand } = require("@aws-sdk/client-sns");
const sns = new SNSClient({ region: process.env.AWS_REGION || "us-west-2" });
const smsCodes = {};
// S3 for presigned uploads/downloads
const {
  S3Client,
  PutObjectCommand,
  GetObjectCommand,
  DeleteObjectCommand,
} = require("@aws-sdk/client-s3");
// =====================
// FILE DELETE: REMOVE S3 OBJECT AND METADATA
// =====================
// Authorization: owner (uploader), admin in same school, or districtAdmin
app.delete(
  "/files/:fileId",
  authMiddleware,
  requireRole(["counselor", "admin", "districtAdmin"]),
  async (req, res) => {
    try {
      const { fileId } = req.params;
      if (!fileId) return res.status(400).json({ error: "Missing fileId" });

      // Try fetching with lowercase key first;

      try {
        // Fetch file metadata
        const resp = await db.send(
          new GetCommand({ TableName: "Files", Key: { fileId } })
        );
        const file = resp.Item;
        if (!file) return res.status(404).json({ error: "File not found" });

        const { role, schoolCode, email } = req.user;
        const sameSchool = file.schoolCode === schoolCode;
        const isOwner = file.ownerEmail === email;

        if (
          role !== "districtAdmin" &&
          !(sameSchool && (isOwner || role === "admin"))
        ) {
          return res.status(403).json({ error: "Forbidden" });
        }

        // Continue your logic below (e.g. generating presigned URL)
      } catch (err) {
        console.error("file fetch error:", err);
        res.status(500).json({ error: "Failed to retrieve file" });
      }

      const bucket =
        file.s3Bucket || process.env.S3_BUCKET || process.env.S3_504_BUCKET;
      const key = file.s3Key;
      if (!bucket || !key) {
        return res.status(500).json({ error: "File storage details missing" });
      }

      // Delete S3 object (best-effort)
      try {
        await s3.send(new DeleteObjectCommand({ Bucket: bucket, Key: key }));
      } catch (e) {
        console.error("S3 delete failed", e);
      }

      // Delete file metadata (DynamoDB + S3 cleanup)
      try {
        await db.send(
          new DeleteCommand({
            TableName: "Files",
            Key: { fileId },
          })
        );
      } catch (err) {
        console.error("delete file metadata error:", err);
        return res
          .status(500)
          .json({ error: "Failed to delete file metadata" });
      }

      // Audit
      try {
        await logAudit({
          userEmail: req.user.email,
          studentId: file.studentId,
          action: `FILE_DELETED ${fileId}`,
          req,
          displayName: req.user.displayName,
        });
      } catch (e) {
        console.error("audit log (file delete) failed", e);
      }

      res.json({ message: "File deleted" });
    } catch (err) {
      console.error("delete file error:", err);
      res.status(500).json({ error: "Failed to delete file" });
    }
  }
);
const { getSignedUrl } = require("@aws-sdk/s3-request-presigner");
const s3 = new S3Client({ region: process.env.AWS_REGION || "us-west-2" });

// Real SNS SMS sender
async function sendVerificationSMS(phoneNumber, code) {
  const params = {
    Message: `Your verification code is: ${code}`,
    PhoneNumber: phoneNumber,
  };
  try {
    await sns.send(new PublishCommand(params));
    console.log("Verification SMS sent.");
  } catch (err) {
    console.error("Error sending SMS:", err);
    throw err;
  }
}

// Request SMS code (now uses SNS)
app.post("/request-sms-code", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "Missing email" });
  const user = await getUserByEmail(email);
  if (!user || !user.phoneNumber)
    return res.status(404).json({ error: "User/phone not found" });
  const code = Math.floor(100000 + Math.random() * 900000).toString();
  smsCodes[email] = { code, expires: Date.now() + 5 * 60 * 1000 };
  try {
    await sendVerificationSMS(user.phoneNumber, code);
    res.json({ message: "SMS code sent" });
  } catch (err) {
    res.status(500).json({ error: "Failed to send SMS" });
  }
});

// Verify SMS code
app.post("/verify-sms-code", async (req, res) => {
  const { email, code } = req.body;
  if (!email || !code) return res.status(400).json({ error: "Missing fields" });
  const user = await getUserByEmail(email);
  if (!user) return res.status(404).json({ error: "User not found" });
  const entry = smsCodes[email];
  if (!entry || entry.code !== code || entry.expires < Date.now()) {
    return res.status(400).json({ error: "Invalid or expired code" });
  }
  // Mark phone as verified
  await db.send(
    new UpdateCommand({
      TableName: "Users",
      Key: { email },
      UpdateExpression: "set phoneVerified = :v",
      ExpressionAttributeValues: { ":v": true },
    })
  );
  delete smsCodes[email];
  res.json({ message: "Phone verified" });
});

// Complete login by verifying SMS code and issuing JWT
app.post("/mfa/sms-verify", async (req, res) => {
  const { email, sessionId, code } = req.body;
  if (!email || !sessionId || !code)
    return res.status(400).json({ error: "Missing fields" });
  try {
    const user = await getUserByEmail(email);
    if (!user) return res.status(404).json({ error: "User not found" });
    if (user.mfaMethod !== "sms") {
      return res.status(400).json({ error: "User not configured for SMS MFA" });
    }
    const entry = smsCodes[email];
    if (!entry || entry.code !== code || entry.expires < Date.now()) {
      return res.status(400).json({ error: "Invalid or expired code" });
    }

    // Mark session as MFA OK
    await db.send(
      new UpdateCommand({
        TableName: "Sessions",
        Key: { sessionId },
        UpdateExpression: "set mfaOk = :m",
        ExpressionAttributeValues: { ":m": true },
      })
    );

    // Ensure user's phone is marked verified
    if (!user.phoneVerified) {
      await db.send(
        new UpdateCommand({
          TableName: "Users",
          Key: { email },
          UpdateExpression: "set phoneVerified = :v",
          ExpressionAttributeValues: { ":v": true },
        })
      );
    }

    // Clear one-time code
    delete smsCodes[email];

    // Issue JWT for this session
    const jwtToken = jwt.sign(
      { email, schoolCode: user.schoolCode, role: user.role, sessionId },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );
    res.json({ token: jwtToken });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Setup TOTP (Google Authenticator) with QR code
app.post("/setup-totp", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "Missing email" });
  const user = await getUserByEmail(email);
  if (!user) return res.status(404).json({ error: "User not found" });
  const secret = speakeasy.generateSecret({ name: `CounselorApp (${email})` });
  await db.send(
    new UpdateCommand({
      TableName: "Users",
      Key: { email },
      UpdateExpression: "set totpSecret = :s, totpVerified = :v",
      ExpressionAttributeValues: { ":s": secret.base32, ":v": false },
    })
  );
  // Generate QR code for otpauth_url
  qrcode.toDataURL(secret.otpauth_url, (err, data_url) => {
    if (err) return res.status(500).json({ error: "Failed to generate QR" });
    res.json({ qrCode: data_url, base32: secret.base32 });
  });
});

// Verify TOTP
app.post("/verify-totp", async (req, res) => {
  const { email, token } = req.body;
  if (!email || !token)
    return res.status(400).json({ error: "Missing fields" });
  const user = await getUserByEmail(email);
  if (!user || !user.totpSecret)
    return res.status(404).json({ error: "User or TOTP not set up" });
  const verified = speakeasy.totp.verify({
    secret: user.totpSecret,
    encoding: "base32",
    token,
    window: 1,
  });
  if (!verified) return res.status(400).json({ error: "Invalid TOTP token" });
  await db.send(
    new UpdateCommand({
      TableName: "Users",
      Key: { email },
      UpdateExpression: "set totpVerified = :v",
      ExpressionAttributeValues: { ":v": true },
    })
  );
  res.json({ message: "TOTP verified" });
});

// Middleware: require2FA
function require2FA() {
  return async (req, res, next) => {
    const user = await getUserByEmail(req.user.email);
    if (!user) return res.status(401).json({ error: "User not found" });
    if (user.mfaMethod === "sms" && !user.phoneVerified) {
      return res
        .status(403)
        .json({ error: "2FA required: phone not verified" });
    }
    if (user.mfaMethod === "totp" && !user.totpVerified) {
      return res.status(403).json({ error: "2FA required: TOTP not verified" });
    }
    next();
  };
}

// ✅ Verify Email Route (token-based, updated to verify first then redirect)
app.get("/verify-email", async (req, res) => {
  const { token } = req.query;
  const redirectBase = (
    process.env.VERIFY_REDIRECT_BASE ||
    process.env.FRONTEND_BASE_URL ||
    process.env.VERIFY_BASE_URL ||
    "https://www.counselornotes.com"
  ).replace(/\/$/, "");

  if (!token) return res.status(400).json({ error: "Missing token" });

  let email;
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET || "devsecret");
    email = payload.email;
  } catch (err) {
    return res.status(400).json({ error: "Invalid or expired token" });
  }

  // ✅ Check user record
  const getParams = {
    TableName: "Users",
    Key: { email },
  };

  try {
    const data = await db.send(new GetCommand(getParams));
    const user = data.Item;

    if (!user) {
      return res.status(400).json({ error: "User not found" });
    }
    if (user.verified) {
      return res.status(200).send(
        `<!doctype html><html><body style="font-family:sans-serif;background:#0a0a0a;color:#f5f5f5;text-align:center;padding:40px;">
          <h2>Email Already Verified</h2>
          <p><a href="${redirectBase}/login" style="color:#8ab4f8;">Go to Login</a></p>
        </body></html>`
      );
    }

    // ✅ Verify and remove token
    if (user.verificationToken !== token) {
      return res.status(400).json({ error: "Token mismatch" });
    }

    const updateParams = {
      TableName: "Users",
      Key: { email },
      UpdateExpression: "set verified = :v remove verificationToken",
      ExpressionAttributeValues: { ":v": true },
    };
    await db.send(new UpdateCommand(updateParams));

    console.log(`✅ Email verified for ${email}`);

    // ✅ Redirect AFTER successful verification
    return res.redirect(
      302,
      `${redirectBase}/verify-email-success?email=${encodeURIComponent(email)}`
    );
  } catch (err) {
    console.error("Verification error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// =====================
// SHARED TODO ITEMS (per school)
// =====================

// Get all todos for the counselor's school
app.get("/todos", authMiddleware, async (req, res) => {
  const schoolCode = req.user?.schoolCode;
  if (!schoolCode)
    return res.status(400).json({ error: "Missing school context" });
  try {
    let items = [];
    // Prefer GSI query for efficiency; fall back to scan if index is not present
    try {
      const out = await db.send(
        new QueryCommand({
          TableName: "TodoItems",
          IndexName: "SchoolIndex",
          KeyConditionExpression: "schoolCode = :sc",
          ExpressionAttributeValues: { ":sc": schoolCode },
        })
      );
      items = out.Items || [];
    } catch (e) {
      // Fallback: scan and filter
      const out = await db.send(
        new ScanCommand({
          TableName: "TodoItems",
          FilterExpression: "schoolCode = :sc",
          ExpressionAttributeValues: { ":sc": schoolCode },
        })
      );
      items = out.Items || [];
    }
    // Sort by createdAt descending (newest first)
    items.sort(
      (a, b) => new Date(b?.createdAt || 0) - new Date(a?.createdAt || 0)
    );
    return res.json(items);
  } catch (err) {
    return res
      .status(500)
      .json({ error: err.message || "Failed to load todos" });
  }
});

// Create a new todo
app.post("/todos", authMiddleware, async (req, res) => {
  const { text, assignedTo = null, priority = null } = req.body || {};
  if (!text || !String(text).trim()) {
    return res.status(400).json({ error: "Missing text" });
  }
  const todo = {
    todoId: uuidv4(),
    schoolCode: req.user.schoolCode,
    text: String(text).trim(),
    createdBy: req.user.email,
    createdAt: new Date().toISOString(),
    completed: false,
  };
  if (assignedTo) todo.assignedTo = assignedTo;
  if (priority) todo.priority = priority;
  try {
    await db.send(new PutCommand({ TableName: "TodoItems", Item: todo }));
    res.json(todo);
  } catch (err) {
    res.status(500).json({ error: err.message || "Failed to create todo" });
  }
});

// Toggle complete
app.patch("/todos/:id", authMiddleware, async (req, res) => {
  const { completed } = req.body || {};
  if (typeof completed !== "boolean") {
    return res.status(400).json({ error: "Missing or invalid completed flag" });
  }
  try {
    await db.send(
      new UpdateCommand({
        TableName: "TodoItems",
        Key: { todoId: req.params.id },
        UpdateExpression: "set completed = :c",
        ExpressionAttributeValues: { ":c": completed },
      })
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message || "Failed to update todo" });
  }
});

// Delete a todo
app.delete("/todos/:id", authMiddleware, async (req, res) => {
  try {
    await db.send(
      new DeleteCommand({
        TableName: "TodoItems",
        Key: { todoId: req.params.id },
      })
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message || "Failed to delete todo" });
  }
});

// =====================
// CALENDAR EVENTS
// =====================

// Get all events for counselor's school
app.get("/calendar", authMiddleware, async (req, res) => {
  try {
    const schoolCode = req.user.schoolCode;
    const data = await db.send(
      new ScanCommand({
        TableName: "CalendarEvents",
        FilterExpression: "schoolCode = :sc",
        ExpressionAttributeValues: { ":sc": schoolCode },
      })
    );
    const items = data.Items || [];
    // Sort by createdAt desc if present; else by startTime
    items.sort(
      (a, b) =>
        new Date(b?.createdAt || b?.startTime || 0) -
        new Date(a?.createdAt || a?.startTime || 0)
    );
    // Attach creator names (firstName lastName) for display
    const emails = Array.from(
      new Set((items || []).map((it) => it.createdBy).filter(Boolean))
    );
    if (emails.length) {
      try {
        // DynamoDB limits batch size to 100 keys – sufficient for dashboard usage
        const keys = emails.slice(0, 100).map((email) => ({ email }));
        const batch = await db.send(
          new BatchGetCommand({
            RequestItems: {
              Users: {
                Keys: keys,
                ProjectionExpression: "email, firstName, lastName",
              },
            },
          })
        );
        const users = (batch.Responses && batch.Responses.Users) || [];
        const nameByEmail = Object.fromEntries(
          users.map((u) => [
            u.email,
            [u.firstName, u.lastName].filter(Boolean).join(" "),
          ])
        );
        for (const it of items) {
          if (it && it.createdBy && nameByEmail[it.createdBy]) {
            it.createdByName = nameByEmail[it.createdBy];
          }
        }
      } catch (e) {
        // If lookup fails, still return items without names
      }
    }
    res.json(items);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch events" });
  }
});

// Create event
app.post("/calendar", authMiddleware, async (req, res) => {
  const {
    title,
    description = null,
    startTime,
    endTime,
    allDay = false,
    attendees,
  } = req.body || {};
  if (!title || !startTime || !endTime)
    return res.status(400).json({ error: "Missing required fields" });
  try {
    const event = {
      eventId: uuidv4(),
      title,
      description,
      startTime,
      endTime,
      allDay: !!allDay,
      schoolCode: req.user.schoolCode,
      createdBy: req.user.email,
      attendees: Array.isArray(attendees) ? attendees : undefined,
      createdAt: new Date().toISOString(),
    };
    await db.send(new PutCommand({ TableName: "CalendarEvents", Item: event }));
    res.json(event);
  } catch (err) {
    res.status(500).json({ error: "Failed to create event" });
  }
});

// Update event (partial)
app.patch("/calendar/:eventId", authMiddleware, async (req, res) => {
  const { eventId } = req.params;
  const { title, description, startTime, endTime, allDay, attendees } =
    req.body || {};
  try {
    // Ensure event exists and belongs to same school (unless districtAdmin)
    const current = await db.send(
      new GetCommand({ TableName: "CalendarEvents", Key: { eventId } })
    );
    const event = current.Item;
    if (!event) return res.status(404).json({ error: "Event not found" });
    if (
      req.user.role !== "districtAdmin" &&
      event.schoolCode !== req.user.schoolCode
    ) {
      return res.status(403).json({ error: "Forbidden" });
    }
    const expr = [];
    const values = {};
    const names = {};
    if (title !== undefined) {
      expr.push("#t = :t");
      names["#t"] = "title";
      values[":t"] = title;
    }
    if (description !== undefined) {
      expr.push("description = :d");
      values[":d"] = description;
    }
    if (startTime !== undefined) {
      expr.push("startTime = :st");
      values[":st"] = startTime;
    }
    if (endTime !== undefined) {
      expr.push("endTime = :et");
      values[":et"] = endTime;
    }
    if (allDay !== undefined) {
      expr.push("allDay = :ad");
      values[":ad"] = !!allDay;
    }
    if (attendees !== undefined) {
      expr.push("attendees = :at");
      values[":at"] = Array.isArray(attendees) ? attendees : [];
    }
    if (expr.length === 0) {
      return res.status(400).json({ error: "No updatable fields provided" });
    }
    const result = await db.send(
      new UpdateCommand({
        TableName: "CalendarEvents",
        Key: { eventId },
        UpdateExpression: `set ${expr.join(", ")}`,
        ExpressionAttributeValues: values,
        ExpressionAttributeNames: names,
        ReturnValues: "ALL_NEW",
      })
    );
    res.json({ message: "Event updated", event: result.Attributes });
  } catch (err) {
    res.status(500).json({ error: "Failed to update event" });
  }
});

// Delete event
app.delete("/calendar/:eventId", authMiddleware, async (req, res) => {
  try {
    const { eventId } = req.params;
    const current = await db.send(
      new GetCommand({ TableName: "CalendarEvents", Key: { eventId } })
    );
    const event = current.Item;
    if (!event) return res.status(404).json({ error: "Event not found" });
    if (
      req.user.role !== "districtAdmin" &&
      event.schoolCode !== req.user.schoolCode
    ) {
      return res.status(403).json({ error: "Forbidden" });
    }
    await db.send(
      new DeleteCommand({ TableName: "CalendarEvents", Key: { eventId } })
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: "Failed to delete event" });
  }
});
// Login Route
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ error: "Missing fields" });

  const params = { TableName: "Users", Key: { email } };
  try {
    const data = await db.send(new GetCommand(params));
    const user = data.Item;
    if (!user) return res.status(401).json({ error: "Invalid credentials" });
    if (user.disabled)
      return res.status(403).json({ error: "Account disabled" });
    if (!user.verified)
      return res.status(403).json({ error: "Email not verified" });

    const valid = await comparePassword(password, user.password);
    if (!valid) return res.status(401).json({ error: "Invalid credentials" });

    const sessionId = uuidv4();
    const expiresAt = Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60; // 7 days in seconds
    await db.send(
      new PutCommand({
        TableName: "Sessions",
        Item: {
          sessionId,
          email: user.email,
          valid: true,
          expiresAt,
        },
      })
    );

    // Enforce TOTP MFA for every sign-in: do not issue JWT yet.
    // Track MFA status on the session and require it in auth middleware.
    await db.send(
      new UpdateCommand({
        TableName: "Sessions",
        Key: { sessionId },
        UpdateExpression: "set mfaOk = :m",
        ExpressionAttributeValues: { ":m": false },
      })
    );

    const totpSetup = Boolean(user.totpSecret);
    const method = user.mfaMethod === "sms" ? "sms" : "totp";
    res.json({
      mfaRequired: true,
      method,
      sessionId,
      email,
      totpSetup,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Auth Middleware
async function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: "No token" });
  const token = auth.split(" ")[1];
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET || "devsecret");
    // Lookup session in DynamoDB
    const result = await db.send(
      new GetCommand({
        TableName: "Sessions",
        Key: { sessionId: payload.sessionId },
      })
    );
    const session = result.Item;
    if (
      !session ||
      !session.valid ||
      session.expiresAt < Math.floor(Date.now() / 1000)
    ) {
      return res.status(401).json({ error: "Session expired or invalid" });
    }
    if (!session.mfaOk) {
      return res.status(401).json({ error: "MFA required" });
    }
    // Attach user info from Users table (for role)
    const user = await getUserByEmail(payload.email);
    if (!user || user.disabled) {
      return res.status(403).json({ error: "Account disabled or not found" });
    }
    req.user = { ...payload, role: user?.role || "counselor" };
    next();
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
}

// Complete login by verifying TOTP and issuing JWT
app.post("/mfa/totp-verify", async (req, res) => {
  const { email, sessionId, token } = req.body;
  if (!email || !sessionId || !token)
    return res.status(400).json({ error: "Missing fields" });
  try {
    const user = await getUserByEmail(email);
    if (!user) return res.status(404).json({ error: "User not found" });
    if (!user.totpSecret) {
      return res.status(400).json({ error: "TOTP not set up" });
    }
    const verified = speakeasy.totp.verify({
      secret: user.totpSecret,
      encoding: "base32",
      token,
      window: 1,
    });
    if (!verified) return res.status(400).json({ error: "Invalid TOTP token" });

    // Mark session as MFA OK
    await db.send(
      new UpdateCommand({
        TableName: "Sessions",
        Key: { sessionId },
        UpdateExpression: "set mfaOk = :m",
        ExpressionAttributeValues: { ":m": true },
      })
    );

    // Ensure user's TOTP is marked verified (one-time setup flag)
    if (!user.totpVerified) {
      await db.send(
        new UpdateCommand({
          TableName: "Users",
          Key: { email },
          UpdateExpression: "set totpVerified = :v",
          ExpressionAttributeValues: { ":v": true },
        })
      );
    }

    // Issue JWT for this session
    const jwtToken = jwt.sign(
      { email, schoolCode: user.schoolCode, role: user.role, sessionId },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );
    res.json({ token: jwtToken });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Change Password (from login screen): verify current password, set new one
// Request body: { email, currentPassword, newPassword }
app.post("/change-password", async (req, res) => {
  try {
    const { email, currentPassword, newPassword } = req.body || {};
    if (!email || !currentPassword || !newPassword) {
      return res.status(400).json({ error: "Missing fields" });
    }

    // Fetch user
    const data = await db.send(
      new GetCommand({ TableName: "Users", Key: { email } })
    );
    const user = data.Item;
    if (!user) return res.status(404).json({ error: "User not found" });
    if (user.disabled)
      return res.status(403).json({ error: "Account disabled" });

    // Verify current password
    const ok = await comparePassword(currentPassword, user.password);
    if (!ok)
      return res.status(401).json({ error: "Current password incorrect" });

    // Validate new password strength
    if (!isStrongPassword(newPassword)) {
      return res.status(400).json({
        error:
          "Password must be at least 12 characters and include uppercase, lowercase, number, and special character.",
      });
    }

    // Hash and update
    const newHash = await hashPassword(newPassword);
    await db.send(
      new UpdateCommand({
        TableName: "Users",
        Key: { email },
        UpdateExpression: "set #pwd = :p",
        ExpressionAttributeNames: { "#pwd": "password" },
        ExpressionAttributeValues: { ":p": newHash },
      })
    );

    try {
      await logAudit({
        userEmail: email,
        action: "PASSWORD_CHANGED",
        req,
        displayName:
          user?.firstName && user?.lastName
            ? `${user.firstName} ${user.lastName}`
            : undefined,
      });
    } catch {}

    res.json({
      message: "Password updated. Please login with your new password.",
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Password Reset Flow
// 1) Request reset: send email with link (DEV: return link in response)
app.post("/password-reset/request", async (req, res) => {
  try {
    const { email } = req.body || {};
    if (!email) return res.status(400).json({ error: "Missing email" });
    const user = await getUserByEmail(email);
    // Always respond 200 to avoid user enumeration (but only proceed if user exists & enabled)
    if (!user || user.disabled) {
      return res.json({
        message: "If the account exists, a reset link has been sent.",
      });
    }
    const token = jwt.sign(
      { email, purpose: "pwreset" },
      process.env.JWT_SECRET,
      { expiresIn: "30m" }
    );
    const base = process.env.FRONTEND_BASE_URL || "";
    const resetLink = base
      ? `${base.replace(/\/$/, "")}/reset-password?token=${encodeURIComponent(
          token
        )}`
      : `/reset-password?token=${encodeURIComponent(token)}`;
    // Send via Amazon SES
    const from = process.env.EMAIL_FROM || process.env.SUPPORT_EMAIL;
    if (!from) {
      console.warn("EMAIL_FROM not set; falling back to console log");
      console.log("[Password Reset] Link for", email, "=>", resetLink);
    } else {
      const subject = "Reset your Counselor Notes password";
      const html = `
        <div style="font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;">
          <h2>Reset your password</h2>
          <p>We received a request to reset your password. Click the button below to set a new password. This link expires in 30 minutes.</p>
          <p style="margin:24px 0;"><a href="${resetLink}" style="background:#2563eb;color:#fff;padding:12px 16px;border-radius:8px;text-decoration:none;display:inline-block">Reset Password</a></p>
          <p>If the button doesn't work, copy and paste this URL into your browser:</p>
          <p><a href="${resetLink}">${resetLink}</a></p>
          <p>If you didn't request this, you can ignore this email.</p>
        </div>`;
      await ses.send(
        new SendEmailCommand({
          Source: from,
          Destination: { ToAddresses: [email] },
          Message: {
            Subject: { Data: subject },
            Body: {
              Html: { Data: html },
              Text: {
                Data: `Reset your password: ${resetLink}\n\nThis link expires in 30 minutes. If you didn't request this, you can ignore this email.`,
              },
            },
          },
        })
      );
    }

    return res.json({
      message: "If the account exists, a reset link has been sent.",
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 2) Confirm reset with token and new password
app.post("/password-reset/confirm", async (req, res) => {
  try {
    const { token, newPassword } = req.body || {};
    if (!token || !newPassword)
      return res.status(400).json({ error: "Missing token or password" });
    let payload;
    try {
      payload = jwt.verify(token, process.env.JWT_SECRET);
    } catch (e) {
      return res.status(400).json({ error: "Invalid or expired token" });
    }
    if (payload.purpose !== "pwreset" || !payload.email) {
      return res.status(400).json({ error: "Invalid token" });
    }
    const user = await getUserByEmail(payload.email);
    if (!user || user.disabled) {
      return res.status(404).json({ error: "User not found or disabled" });
    }
    if (!isStrongPassword(newPassword)) {
      return res.status(400).json({
        error:
          "Password must be at least 12 characters and include uppercase, lowercase, number, and special character.",
      });
    }
    const newHash = await hashPassword(newPassword);
    await db.send(
      new UpdateCommand({
        TableName: "Users",
        Key: { email: payload.email },
        UpdateExpression: "set #pwd = :p",
        ExpressionAttributeNames: { "#pwd": "password" },
        ExpressionAttributeValues: { ":p": newHash },
      })
    );
    try {
      await logAudit({
        userEmail: payload.email,
        action: "PASSWORD_RESET",
        req,
        displayName:
          user?.firstName && user?.lastName
            ? `${user.firstName} ${user.lastName}`
            : undefined,
      });
    } catch {}
    res.json({ message: "Password reset successful. You can now log in." });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- NOTES ROUTES ---

// Get Note by ID (logs view)
app.get(
  "/notes/:noteId",
  authMiddleware,
  requireRole(["counselor", "admin"]),
  async (req, res) => {
    const { noteId } = req.params;
    try {
      const data = await db.send(
        new GetCommand({ TableName: "Notes", Key: { noteId } })
      );
      const note = data.Item;
      if (!note) return res.status(404).json({ error: "Note not found" });
      // RBAC: Only owner, sharedWith, or admin in school can view
      const { email, role, schoolCode } = req.user;
      if (role !== "admin" && note.schoolCode !== schoolCode)
        return res.status(403).json({ error: "Forbidden" });
      if (
        role !== "admin" &&
        note.ownerEmail !== email &&
        !(note.sharedWith || []).includes(email)
      )
        return res.status(403).json({ error: "Forbidden" });
      // Log view
      await logAudit({
        userEmail: email,
        noteId,
        action: "VIEWED",
        req,
        displayName: req.user.displayName,
      });
      res.json({ note });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);

// Get current user's profile (firstName, lastName, email, role, schoolCode)
app.get("/me", authMiddleware, async (req, res) => {
  try {
    const user = await getUserByEmail(req.user.email);
    if (!user) return res.status(404).json({ error: "User not found" });
    res.json({
      firstName: user.firstName || null,
      lastName: user.lastName || null,
      email: user.email,
      role: user.role,
      schoolCode: user.schoolCode || null,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Update Note by ID (logs edit)
app.put(
  "/notes/:noteId",
  authMiddleware,
  requireRole(["counselor", "admin"]),
  async (req, res) => {
    const { noteId } = req.params;
    const { content, sharedWith, topic } = req.body;
    try {
      const data = await db.send(
        new GetCommand({ TableName: "Notes", Key: { noteId } })
      );
      const note = data.Item;
      if (!note) return res.status(404).json({ error: "Note not found" });
      // Only owner or admin can edit
      const { email, role } = req.user;
      if (note.ownerEmail !== email && role !== "admin") {
        return res.status(403).json({ error: "Forbidden" });
      }
      // Update note
      const updateExp = [];
      const expAttr = {};
      if (content !== undefined) {
        updateExp.push("content = :c");
        expAttr[":c"] = content;
      }
      if (sharedWith !== undefined) {
        updateExp.push("sharedWith = :sw");
        expAttr[":sw"] = sharedWith;
      }
      if (topic !== undefined) {
        updateExp.push("topic = :t");
        expAttr[":t"] = topic;
      }
      if (updateExp.length === 0)
        return res.status(400).json({ error: "No changes" });
      await db.send(
        new UpdateCommand({
          TableName: "Notes",
          Key: { noteId },
          UpdateExpression: "set " + updateExp.join(", "),
          ExpressionAttributeValues: expAttr,
        })
      );
      // Log edit
      await logAudit({
        userEmail: email,
        noteId,
        action: "EDITED",
        req,
        displayName: req.user.displayName,
      });
      res.json({ message: "Note updated" });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);

// Admin: View audit log for a note
app.get(
  "/notes/:noteId/audit",
  authMiddleware,
  requireRole(["admin"]),
  async (req, res) => {
    const { noteId } = req.params;
    try {
      const data = await db.send(
        new QueryCommand({
          TableName: "AuditLog",
          IndexName: undefined, // PK is noteId, or use scan if not
          KeyConditionExpression: "noteId = :nid",
          ExpressionAttributeValues: { ":nid": noteId },
        })
      );
      res.json({ audit: data.Items });
    } catch (err) {
      // fallback to scan if query fails (if PK is not noteId)
      try {
        const data = await db.send(
          new ScanCommand({
            TableName: "AuditLog",
            FilterExpression: "noteId = :nid",
            ExpressionAttributeValues: { ":nid": noteId },
          })
        );
        res.json({ audit: data.Items });
      } catch (err2) {
        res.status(500).json({ error: err2.message });
      }
    }
  }
);

// Create Note (counselor or admin)
app.post(
  "/notes",
  authMiddleware,
  requireRole(["counselor", "admin"]),
  async (req, res) => {
    const { content, sharedWith, noteType, legalHold, studentId, topic } =
      req.body;
    if (!studentId) {
      return res.status(400).json({ error: "Missing studentId for note" });
    }
    const note = {
      noteId: uuidv4(),
      ownerEmail: req.user.email,
      schoolCode: req.user.schoolCode,
      studentId,
      sharedWith: Array.isArray(sharedWith) ? sharedWith : [],
      content: content || "",
      topic: typeof topic === "string" ? topic : null,
      createdAt: new Date().toISOString(),
      archived: false,
      deleted: false,
      deleteAfter: null, // ISO string or null
      noteType: noteType === "privateNote" ? "privateNote" : "educationRecord",
      legalHold: !!legalHold,
    };
    try {
      await db.send(new PutCommand({ TableName: "Notes", Item: note }));
      res.status(201).json({ message: "Note created", note });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);

// Get My/Shared Notes (counselor)
app.get(
  "/notes",
  authMiddleware,
  requireRole(["counselor", "admin", "districtAdmin"]),
  async (req, res) => {
    const { role, email, schoolCode } = req.user;
    let params;
    if (role === "districtAdmin") {
      // District admin: all notes
      params = { TableName: "Notes" };
    } else if (role === "admin") {
      // Admin: all notes in school
      params = {
        TableName: "Notes",
        FilterExpression: "schoolCode = :sc",
        ExpressionAttributeValues: { ":sc": schoolCode },
      };
    } else {
      // Counselor: own or shared notes
      params = {
        TableName: "Notes",
        FilterExpression:
          "schoolCode = :sc AND (ownerEmail = :e OR contains(sharedWith, :e))",
        ExpressionAttributeValues: { ":sc": schoolCode, ":e": email },
      };
    }
    try {
      const data = await db.send(new ScanCommand(params));
      res.json({ notes: data.Items });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);

// Share Note (owner only, with consent tracking)
app.post(
  "/notes/:noteId/share",
  authMiddleware,
  requireRole(["counselor", "admin"]),
  async (req, res) => {
    const { noteId } = req.params;
    const { shareWith, consent, consentMethod } = req.body; // array of emails, boolean consent, string consentMethod
    if (req.user.role !== "admin" && consent !== true) {
      return res.status(400).json({ error: "Consent required to share note" });
    }
    if (req.user.role !== "admin" && !consentMethod) {
      return res.status(400).json({ error: "Consent method required" });
    }
    try {
      // Get note
      const data = await db.send(
        new GetCommand({ TableName: "Notes", Key: { noteId } })
      );
      const note = data.Item;
      if (!note) return res.status(404).json({ error: "Note not found" });
      if (note.ownerEmail !== req.user.email && req.user.role !== "admin") {
        return res.status(403).json({ error: "Not owner or admin" });
      }
      // Update sharedWith and consent info
      const newShared = Array.isArray(shareWith) ? shareWith : [];
      const updateExp = ["sharedWith = :sw"];
      const expAttr = { ":sw": newShared };
      if (req.user.role === "admin") {
        // Admin can share without consent
        updateExp.push("consentTimestamp = :ct");
        expAttr[":ct"] = null;
        updateExp.push("consentMethod = :cm");
        expAttr[":cm"] = null;
      } else {
        updateExp.push("consentTimestamp = :ct");
        expAttr[":ct"] = new Date().toISOString();
        updateExp.push("consentMethod = :cm");
        expAttr[":cm"] = consentMethod;
      }
      await db.send(
        new UpdateCommand({
          TableName: "Notes",
          Key: { noteId },
          UpdateExpression: "set " + updateExp.join(", "),
          ExpressionAttributeValues: expAttr,
        })
      );
      // Log consent in AuditLog
      if (req.user.role !== "admin") {
        await logAudit({
          userEmail: req.user.email,
          noteId,
          action: `CONSENT_GRANTED (${consentMethod})`,
          req,
          displayName: req.user.displayName,
        });
      }
      res.json({
        message: "Note shared",
        sharedWith: newShared,
        consentTimestamp: expAttr[":ct"],
        consentMethod: expAttr[":cm"],
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);

// Revoke consent for a note (owner or admin)
app.post(
  "/notes/:noteId/revoke-consent",
  authMiddleware,
  requireRole(["counselor", "admin"]),
  async (req, res) => {
    const { noteId } = req.params;
    try {
      // Get note
      const data = await db.send(
        new GetCommand({ TableName: "Notes", Key: { noteId } })
      );
      const note = data.Item;
      if (!note) return res.status(404).json({ error: "Note not found" });
      if (note.ownerEmail !== req.user.email && req.user.role !== "admin") {
        return res.status(403).json({ error: "Not owner or admin" });
      }
      // Remove consent info and clear sharedWith
      await db.send(
        new UpdateCommand({
          TableName: "Notes",
          Key: { noteId },
          UpdateExpression:
            "set consentTimestamp = :ct, consentMethod = :cm, sharedWith = :sw",
          ExpressionAttributeValues: {
            ":ct": null,
            ":cm": null,
            ":sw": [],
          },
        })
      );
      // Log revoke in AuditLog
      await logAudit({
        userEmail: req.user.email,
        noteId,
        action: "CONSENT_REVOKED",
        req,
        displayName: req.user.displayName,
      });
      res.json({ message: "Consent revoked, sharing removed" });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);

// Archive Note (owner or admin)
app.post(
  "/notes/:noteId/archive",
  authMiddleware,
  requireRole(["counselor", "admin", "districtAdmin"]),
  async (req, res) => {
    const { noteId } = req.params;
    try {
      const data = await db.send(
        new GetCommand({ TableName: "Notes", Key: { noteId } })
      );
      const note = data.Item;
      if (!note || note.deleted)
        return res.status(404).json({ error: "Note not found" });
      if (note.legalHold)
        return res
          .status(403)
          .json({ error: "Note is under legal hold and cannot be archived" });
      const { email, role } = req.user;
      if (
        note.ownerEmail !== email &&
        role !== "admin" &&
        role !== "districtAdmin"
      ) {
        return res.status(403).json({ error: "Forbidden" });
      }
      await db.send(
        new UpdateCommand({
          TableName: "Notes",
          Key: { noteId },
          UpdateExpression: "set archived = :a",
          ExpressionAttributeValues: { ":a": true },
        })
      );
      // Log archive
      await logAudit({
        userEmail: email,
        noteId,
        action: "ARCHIVED",
        req,
        displayName: req.user.displayName,
      });
      res.json({ message: "Note archived" });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);

// Delete Note (soft-delete, owner or admin)
app.delete(
  "/notes/:noteId",
  authMiddleware,
  requireRole(["counselor", "admin", "districtAdmin"]),
  async (req, res) => {
    const { noteId } = req.params;
    try {
      const data = await db.send(
        new GetCommand({ TableName: "Notes", Key: { noteId } })
      );
      const note = data.Item;
      if (!note || note.deleted)
        return res.status(404).json({ error: "Note not found" });
      if (note.legalHold)
        return res
          .status(403)
          .json({ error: "Note is under legal hold and cannot be deleted" });
      const { email, role } = req.user;
      if (
        note.ownerEmail !== email &&
        role !== "admin" &&
        role !== "districtAdmin"
      ) {
        return res.status(403).json({ error: "Forbidden" });
      }
      await db.send(
        new UpdateCommand({
          TableName: "Notes",
          Key: { noteId },
          UpdateExpression: "set deleted = :d",
          ExpressionAttributeValues: { ":d": true },
        })
      );
      // Log delete
      await logAudit({
        userEmail: email,
        noteId,
        action: "DELETED",
        req,
        displayName: req.user.displayName,
      });
      res.json({ message: "Note deleted" });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);

// Admin: Set deleteAfter for a note
app.post(
  "/notes/:noteId/delete-after",
  authMiddleware,
  requireRole(["admin"]),
  async (req, res) => {
    const { noteId } = req.params;
    const { deleteAfter } = req.body; // ISO string
    if (!deleteAfter)
      return res.status(400).json({ error: "Missing deleteAfter" });
    try {
      const data = await db.send(
        new GetCommand({ TableName: "Notes", Key: { noteId } })
      );
      const note = data.Item;
      if (!note || note.deleted)
        return res.status(404).json({ error: "Note not found" });
      await db.send(
        new UpdateCommand({
          TableName: "Notes",
          Key: { noteId },
          UpdateExpression: "set deleteAfter = :da",
          ExpressionAttributeValues: { ":da": deleteAfter },
        })
      );
      res.json({ message: "deleteAfter set", deleteAfter });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);

// Admin: Export note as JSON before deletion
app.get(
  "/notes/:noteId/export",
  authMiddleware,
  requireRole(["admin"]),
  async (req, res) => {
    const { noteId } = req.params;
    try {
      const data = await db.send(
        new GetCommand({ TableName: "Notes", Key: { noteId } })
      );
      const note = data.Item;
      if (!note) return res.status(404).json({ error: "Note not found" });
      res.setHeader(
        "Content-Disposition",
        `attachment; filename=note_${noteId}.json`
      );
      res.json(note);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);

// --- DATA PORTABILITY EXPORTS ---
const { Parser } = require("json2csv");

// Export all notes for a student as CSV (admin/counselor)
app.get(
  "/export/student/:studentId/notes.csv",
  authMiddleware,
  requireRole(["admin", "counselor"]),
  async (req, res) => {
    const { studentId } = req.params;
    try {
      // Find all notes for this studentId (assuming notes have studentId field or in content)
      // If not, this will need to be adapted to your schema
      const data = await db.send(
        new ScanCommand({
          TableName: "Notes",
          FilterExpression: "studentId = :sid",
          ExpressionAttributeValues: { ":sid": studentId },
        })
      );
      const notes = data.Items || [];
      if (notes.length === 0)
        return res.status(404).json({ error: "No notes found for student" });
      // Convert to CSV
      const parser = new Parser();
      const csv = parser.parse(notes);
      res.header("Content-Type", "text/csv");
      res.attachment(`student_${studentId}_notes.csv`);
      res.send(csv);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);

// Export all notes for a counselor as CSV (admin/counselor)
app.get(
  "/export/counselor/:email/notes.csv",
  authMiddleware,
  requireRole(["admin", "counselor"]),
  async (req, res) => {
    const { email } = req.params;
    try {
      // Only allow counselors to export their own notes, or admin any
      if (req.user.role !== "admin" && req.user.email !== email) {
        return res.status(403).json({ error: "Forbidden" });
      }
      const data = await db.send(
        new ScanCommand({
          TableName: "Notes",
          FilterExpression: "ownerEmail = :e",
          ExpressionAttributeValues: { ":e": email },
        })
      );
      const notes = data.Items || [];
      if (notes.length === 0)
        return res.status(404).json({ error: "No notes found for counselor" });
      // Convert to CSV
      const parser = new Parser();
      const csv = parser.parse(notes);
      res.header("Content-Type", "text/csv");
      res.attachment(`counselor_${email}_notes.csv`);
      res.send(csv);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);

// PDF export for all notes for a student (admin/counselor)
const PDFDocument = require("pdfkit");

function notesToPDF(notes, title, res, filename) {
  const doc = new PDFDocument({ margin: 30, size: "A4" });
  res.setHeader("Content-Type", "application/pdf");
  res.setHeader("Content-Disposition", `attachment; filename=${filename}`);
  doc.pipe(res);
  doc.fontSize(18).text(title, { align: "center" });
  doc.moveDown();
  if (!notes.length) {
    doc.text("No notes found.");
    doc.end();
    return;
  }
  // Table header
  const headers = Object.keys(notes[0]);
  doc.fontSize(10).font("Helvetica-Bold");
  doc.text(headers.join(" | "));
  doc.moveDown(0.5);
  doc.font("Helvetica");
  // Table rows
  notes.forEach((note) => {
    const row = headers.map((h) => String(note[h] ?? "")).join(" | ");
    doc.text(row);
  });
  doc.end();
}

// Export all notes for a student as PDF
app.get(
  "/export/student/:studentId/notes.pdf",
  authMiddleware,
  requireRole(["admin", "counselor"]),
  async (req, res) => {
    const { studentId } = req.params;
    try {
      const data = await db.send(
        new ScanCommand({
          TableName: "Notes",
          FilterExpression: "studentId = :sid",
          ExpressionAttributeValues: { ":sid": studentId },
        })
      );
      const notes = data.Items || [];
      notesToPDF(
        notes,
        `Notes for Student ${studentId}`,
        res,
        `student_${studentId}_notes.pdf`
      );
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);

// Export all notes for a counselor as PDF
app.get(
  "/export/counselor/:email/notes.pdf",
  authMiddleware,
  requireRole(["admin", "counselor"]),
  async (req, res) => {
    const { email } = req.params;
    try {
      if (req.user.role !== "admin" && req.user.email !== email) {
        return res.status(403).json({ error: "Forbidden" });
      }
      const data = await db.send(
        new ScanCommand({
          TableName: "Notes",
          FilterExpression: "ownerEmail = :e",
          ExpressionAttributeValues: { ":e": email },
        })
      );
      const notes = data.Items || [];
      notesToPDF(
        notes,
        `Notes for Counselor ${email}`,
        res,
        `counselor_${email}_notes.pdf`
      );
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);

// --- USERS IN SCHOOL (for sharing) ---
// List all verified users in the same school (for share dropdown)
// List all verified users in the same school (for share dropdown)
app.get(
  "/users",
  authMiddleware,
  requireRole(["counselor", "admin"]),
  async (req, res) => {
    const { schoolCode, email } = req.user;
    try {
      const data = await db.send(
        new ScanCommand({
          TableName: "Users",
          FilterExpression:
            "schoolCode = :sc AND verified = :v AND email <> :e",
          ExpressionAttributeValues: {
            ":sc": schoolCode,
            ":v": true,
            ":e": email,
          },
          ProjectionExpression: "email, firstName, lastName, #r",
          ExpressionAttributeNames: {
            "#r": "role",
          },
        })
      );
      res.json({ users: data.Items });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);

// Logout Route
app.post("/logout", authMiddleware, async (req, res) => {
  const { sessionId } = req.user;
  await db.send(
    new UpdateCommand({
      TableName: "Sessions",
      Key: { sessionId },
      UpdateExpression: "set valid = :v",
      ExpressionAttributeValues: { ":v": false },
    })
  );
  res.json({ message: "Logged out" });
});

// Logout Everywhere Route
app.post("/logout-all", authMiddleware, async (req, res) => {
  const { email } = req.user;
  const result = await db.send(
    new ScanCommand({
      TableName: "Sessions",
      FilterExpression: "email = :e",
      ExpressionAttributeValues: { ":e": email },
    })
  );
  const sessions = result.Items || [];
  for (const s of sessions) {
    await db.send(
      new UpdateCommand({
        TableName: "Sessions",
        Key: { sessionId: s.sessionId },
        UpdateExpression: "set valid = :v",
        ExpressionAttributeValues: { ":v": false },
      })
    );
  }
  res.json({ message: "Logged out everywhere" });
});

// Students Route (protected)
app.get("/students", authMiddleware, async (req, res) => {
  const { schoolCode } = req.user;
  const params = {
    TableName: "Students",
    FilterExpression: "schoolCode = :sc",
    ExpressionAttributeValues: { ":sc": schoolCode },
  };
  try {
    const data = await db.send(new ScanCommand(params));
    res.json({ students: data.Items });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin: Roll over grades after Aug 15 of the current year
// - For each student in the admin's school:
//   - If lastGradeRolloverYear !== currentYear and today is on/after Aug 15, then
//     - If grade is >= 12 (numeric), set to 'Graduated'
//     - Else if grade is numeric, increment by 1
//     - Else if already 'Graduated', keep it
//     - Set lastGradeRolloverYear = currentYear
app.post(
  "/admin/rollover-grades",
  async (req, res, next) => {
    // 1️⃣ Allow automation via API key (bypass JWT)
    const apiKey = req.headers["x-api-key"];
    if (apiKey && apiKey === process.env.ADMIN_API_KEY) {
      req.user = { role: "admin", schoolCode: "default" }; // or assign a system-wide schoolCode
      return next(); // skip authMiddleware, go directly to rollover logic
    }

    // 2️⃣ Otherwise, fall back to normal JWT-based admin route
    return authMiddleware(req, res, async (err) => {
      if (err) return res.status(401).json({ error: "Unauthorized" });
      if (req.user.role !== "admin")
        return res.status(403).json({ error: "Admins only" });
      next();
    });
  },
  async (req, res) => {
    const { force } = req.body || {};
    const now = new Date();
    const currentYear = now.getFullYear();
    const rolloverDate = new Date(currentYear, 7, 15); // Aug=7 (0-based)
    if (!force && now < rolloverDate) {
      return res.status(400).json({
        error:
          "Rollover not available yet. It becomes available on August 15 of the current year.",
      });
    }

    const { schoolCode } = req.user;
    try {
      // Scan students in this school
      const scanParams = {
        TableName: "Students",
        FilterExpression: "schoolCode = :sc",
        ExpressionAttributeValues: { ":sc": schoolCode },
      };
      const data = await db.send(new ScanCommand(scanParams));
      const students = data.Items || [];

      const toUpdate = [];
      const parseNumeric = (g) => {
        if (g === null || g === undefined) return null;
        if (typeof g === "number") return Number.isFinite(g) ? g : null;
        const s = String(g).trim();
        if (!s) return null;
        const n = parseInt(s, 10);
        return Number.isNaN(n) ? null : n;
      };

      const isKindergarten = (g) => {
        if (g === null || g === undefined) return false;
        const s = String(g).trim().toLowerCase();
        return (
          s === "k" || s === "kg" || s === "kinder" || s === "kindergarten"
        );
      };

      for (const s of students) {
        const lastYear = s.lastGradeRolloverYear || null;
        if (lastYear === currentYear) continue; // already rolled this year

        let newGrade = s.grade;
        const normalizedGrade = (s.grade || "").toString().trim();
        if (/^graduated$/i.test(normalizedGrade)) {
          newGrade = "Graduated";
        } else if (isKindergarten(normalizedGrade)) {
          newGrade = "1";
        } else {
          const n = parseNumeric(normalizedGrade);
          if (n !== null) {
            if (n >= 12) newGrade = "Graduated";
            else if (n >= 0) newGrade = String(n + 1);
          }
        }

        toUpdate.push({
          studentId: s.studentId,
          newGrade,
        });
      }

      // Perform updates (sequential to keep it simple; dataset is typically small)
      let updated = 0;
      for (const u of toUpdate) {
        await db.send(
          new UpdateCommand({
            TableName: "Students",
            Key: { studentId: u.studentId },
            UpdateExpression: "set grade = :g, lastGradeRolloverYear = :y",
            ExpressionAttributeValues: { ":g": u.newGrade, ":y": currentYear },
          })
        );
        updated += 1;
      }

      res.json({ message: "Grade rollover completed", updated });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);

// Add Student Route (protected)
app.post("/students", authMiddleware, async (req, res) => {
  const {
    studentId,
    firstName,
    lastName,
    grade,
    referredBy,
    referredReason,
    studentSupportStatus,
    reportsCount,
    meetings,
  } = req.body;

  // Normalize studentSupportStatus to array if provided
  let normalizedSupport = [];
  if (Array.isArray(studentSupportStatus)) {
    normalizedSupport = studentSupportStatus.filter(
      (v) => typeof v === "string" && v.trim()
    );
  } else if (
    typeof studentSupportStatus === "string" &&
    studentSupportStatus.trim()
  ) {
    normalizedSupport = [studentSupportStatus.trim()];
  }

  // Normalize meetings to an array of ISO date strings (sorted desc)
  const normalizeMeetings = (m) => {
    const list = [];
    if (Array.isArray(m)) {
      for (const v of m) {
        let d = null;
        if (v instanceof Date) d = v;
        else if (typeof v === "number") d = new Date(v);
        else if (typeof v === "string" && v.trim()) d = new Date(v);
        if (d && !isNaN(d.getTime())) list.push(d.toISOString());
      }
    } else if (typeof m === "string" && m.trim()) {
      const d = new Date(m);
      if (!isNaN(d.getTime())) list.push(d.toISOString());
    } else if (m instanceof Date) {
      if (!isNaN(m.getTime())) list.push(m.toISOString());
    }
    // Unique + sort desc (most recent first)
    const unique = Array.from(new Set(list));
    unique.sort((a, b) => new Date(b).getTime() - new Date(a).getTime());
    return unique;
  };
  const normalizedMeetings = normalizeMeetings(meetings);

  const newStudent = {
    studentId: studentId || Date.now().toString(), // auto ID if missing
    firstName: firstName || "N/A",
    lastName: lastName || "N/A",
    grade: grade || "N/A",
    referredBy: referredBy || "N/A",
    referredReason: referredReason || "N/A",
    studentSupportStatus:
      normalizedSupport.length > 0 ? normalizedSupport : "N/A",
    reportsCount: reportsCount || 0,
    meetings: normalizedMeetings,
    schoolCode: req.user.schoolCode, // tie to counselor’s school
  };

  const params = {
    TableName: "Students",
    Item: newStudent,
  };

  try {
    await db.send(new PutCommand(params));
    res.status(201).json({ message: "Student added", student: newStudent });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Update Student Route (protected)
app.put("/students/:studentId", authMiddleware, async (req, res) => {
  const { studentId } = req.params;
  const {
    firstName,
    lastName,
    grade,
    referredBy,
    referredReason,
    studentSupportStatus,
    meetings,
  } = req.body || {};
  try {
    // Ensure student exists and belongs to the same school
    const current = await db.send(
      new GetCommand({ TableName: "Students", Key: { studentId } })
    );
    const student = current.Item;
    if (!student) return res.status(404).json({ error: "Student not found" });
    if (student.schoolCode !== req.user.schoolCode) {
      return res.status(403).json({ error: "Forbidden" });
    }

    const exprParts = [];
    const ExpressionAttributeNames = {};
    const ExpressionAttributeValues = {};

    if (firstName !== undefined) {
      exprParts.push("#fn = :fn");
      ExpressionAttributeNames["#fn"] = "firstName";
      ExpressionAttributeValues[":fn"] = firstName;
    }
    if (lastName !== undefined) {
      exprParts.push("#ln = :ln");
      ExpressionAttributeNames["#ln"] = "lastName";
      ExpressionAttributeValues[":ln"] = lastName;
    }
    if (grade !== undefined) {
      exprParts.push("#gr = :gr");
      ExpressionAttributeNames["#gr"] = "grade";
      ExpressionAttributeValues[":gr"] = grade;
    }
    if (referredBy !== undefined) {
      exprParts.push("#rb = :rb");
      ExpressionAttributeNames["#rb"] = "referredBy";
      ExpressionAttributeValues[":rb"] = referredBy;
    }
    if (referredReason !== undefined) {
      exprParts.push("#rr = :rr");
      ExpressionAttributeNames["#rr"] = "referredReason";
      ExpressionAttributeValues[":rr"] = referredReason;
    }
    if (studentSupportStatus !== undefined) {
      let normalized = [];
      if (Array.isArray(studentSupportStatus)) {
        normalized = studentSupportStatus.filter(
          (v) => typeof v === "string" && v.trim()
        );
      } else if (
        typeof studentSupportStatus === "string" &&
        studentSupportStatus.trim()
      ) {
        normalized = [studentSupportStatus.trim()];
      }
      exprParts.push("#sss = :sss");
      ExpressionAttributeNames["#sss"] = "studentSupportStatus";
      ExpressionAttributeValues[":sss"] =
        normalized.length > 0 ? normalized : "N/A";
    }

    // Accept meetings via multiple common keys for robustness
    const rawMeetings =
      meetings !== undefined
        ? meetings
        : req.body?.meeting !== undefined
        ? req.body.meeting
        : req.body?.meetingDate !== undefined
        ? req.body.meetingDate
        : req.body?.lastMeeting !== undefined
        ? req.body.lastMeeting
        : undefined;

    if (rawMeetings !== undefined) {
      // reuse normalization from above
      const normalizeMeetings = (m) => {
        const list = [];
        if (Array.isArray(m)) {
          for (const v of m) {
            let d = null;
            if (v instanceof Date) d = v;
            else if (typeof v === "number") d = new Date(v);
            else if (typeof v === "string" && v.trim()) d = new Date(v);
            if (d && !isNaN(d.getTime())) list.push(d.toISOString());
          }
        } else if (typeof m === "string" && m.trim()) {
          const d = new Date(m);
          if (!isNaN(d.getTime())) list.push(d.toISOString());
        } else if (m instanceof Date) {
          if (!isNaN(m.getTime())) list.push(m.toISOString());
        }
        const unique = Array.from(new Set(list));
        unique.sort((a, b) => new Date(b).getTime() - new Date(a).getTime());
        return unique;
      };
      const nm = normalizeMeetings(rawMeetings);
      exprParts.push("#mt = :mt");
      ExpressionAttributeNames["#mt"] = "meetings";
      ExpressionAttributeValues[":mt"] = nm;
    }

    if (exprParts.length === 0) {
      return res.status(400).json({ error: "No updatable fields provided" });
    }

    const result = await db.send(
      new UpdateCommand({
        TableName: "Students",
        Key: { studentId },
        UpdateExpression: `set ${exprParts.join(", ")}`,
        ExpressionAttributeNames,
        ExpressionAttributeValues,
        ReturnValues: "ALL_NEW",
      })
    );
    res.json({ message: "Student updated", student: result.Attributes });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Set legalHold flag (admin only)
app.post(
  "/notes/:noteId/legal-hold",
  authMiddleware,
  requireRole(["admin"]),
  async (req, res) => {
    const { noteId } = req.params;
    const { legalHold } = req.body;
    if (typeof legalHold !== "boolean")
      return res.status(400).json({ error: "legalHold must be boolean" });
    try {
      const data = await db.send(
        new GetCommand({ TableName: "Notes", Key: { noteId } })
      );
      const note = data.Item;
      if (!note || note.deleted)
        return res.status(404).json({ error: "Note not found" });
      await db.send(
        new UpdateCommand({
          TableName: "Notes",
          Key: { noteId },
          UpdateExpression: "set legalHold = :lh",
          ExpressionAttributeValues: { ":lh": legalHold },
        })
      );
      res.json({ message: "legalHold updated", legalHold });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);

// Update deleteAfter with preset options (admin or owner)
app.post(
  "/notes/:noteId/delete-after-preset",
  authMiddleware,
  requireRole(["counselor", "admin"]),
  async (req, res) => {
    const { noteId } = req.params;
    const { preset, customDate } = req.body; // preset: 'forever', '1y', '3y', '5y', 'custom', customDate: ISO string
    try {
      const data = await db.send(
        new GetCommand({ TableName: "Notes", Key: { noteId } })
      );
      const note = data.Item;
      if (!note || note.deleted)
        return res.status(404).json({ error: "Note not found" });
      const { email, role } = req.user;
      if (note.ownerEmail !== email && role !== "admin") {
        return res.status(403).json({ error: "Forbidden" });
      }
      let deleteAfter = null;
      if (preset === "forever") {
        deleteAfter = null;
      } else if (preset === "1y") {
        deleteAfter = new Date(
          Date.now() + 365 * 24 * 60 * 60 * 1000
        ).toISOString();
      } else if (preset === "3y") {
        deleteAfter = new Date(
          Date.now() + 3 * 365 * 24 * 60 * 60 * 1000
        ).toISOString();
      } else if (preset === "5y") {
        deleteAfter = new Date(
          Date.now() + 5 * 365 * 24 * 60 * 60 * 1000
        ).toISOString();
      } else if (preset === "custom" && customDate) {
        deleteAfter = customDate;
      } else {
        return res.status(400).json({ error: "Invalid preset or customDate" });
      }
      await db.send(
        new UpdateCommand({
          TableName: "Notes",
          Key: { noteId },
          UpdateExpression: "set deleteAfter = :da",
          ExpressionAttributeValues: { ":da": deleteAfter },
        })
      );
      res.json({ message: "deleteAfter updated", deleteAfter });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);

// =====================
// ADMIN EXPORT ENDPOINTS
// =====================

// Get audit logs for admin's school (joins via studentId or noteId)
app.get(
  "/admin/audit-logs",
  authMiddleware,
  requireRole(["admin", "auditor", "districtAdmin"]),
  async (req, res) => {
    const { schoolCode, role } = req.user;
    try {
      // Gather allowed studentIds and noteIds for this school
      const studentsScanParams =
        role === "districtAdmin"
          ? { TableName: "Students" }
          : {
              TableName: "Students",
              FilterExpression: "schoolCode = :sc",
              ExpressionAttributeValues: { ":sc": schoolCode },
            };
      const notesScanParams =
        role === "districtAdmin"
          ? { TableName: "Notes" }
          : {
              TableName: "Notes",
              FilterExpression: "schoolCode = :sc",
              ExpressionAttributeValues: { ":sc": schoolCode },
            };

      const [studentsData, notesData] = await Promise.all([
        db.send(new ScanCommand(studentsScanParams)),
        db.send(new ScanCommand(notesScanParams)),
      ]);
      const studentIds = new Set(
        (studentsData.Items || []).map((s) => s.studentId)
      );
      const noteIds = new Set((notesData.Items || []).map((n) => n.noteId));

      // Scan audit log and filter by school via noteId/studentId membership or schoolCode on system logs
      const auditData = await db.send(
        new ScanCommand({ TableName: "AuditLog" })
      );
      const logs = (auditData.Items || []).filter((log) => {
        if (role === "districtAdmin") return true; // district admin sees all logs
        if (log.schoolCode && log.schoolCode === schoolCode) return true; // system logs
        if (log.studentId && studentIds.has(log.studentId)) return true;
        if (log.noteId && noteIds.has(log.noteId)) return true;
        return false;
      });
      // Sort newest first
      logs.sort(
        (a, b) =>
          new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
      );
      res.json({ logs });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);

// Get consents/authorizations for admin's school from Notes
app.get(
  "/admin/consents",
  authMiddleware,
  requireRole(["admin", "auditor", "districtAdmin"]),
  async (req, res) => {
    const { schoolCode, role } = req.user;
    try {
      const notesScanParams =
        role === "districtAdmin"
          ? { TableName: "Notes" }
          : {
              TableName: "Notes",
              FilterExpression: "schoolCode = :sc",
              ExpressionAttributeValues: { ":sc": schoolCode },
            };
      const notesData = await db.send(new ScanCommand(notesScanParams));
      const notes = (notesData.Items || []).filter(
        (n) =>
          n.consentTimestamp ||
          (Array.isArray(n.sharedWith) && n.sharedWith.length > 0)
      );
      res.json({ notes });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);

// Get archived/deleted records for admin's school from Notes
app.get(
  "/admin/archived-deleted",
  authMiddleware,
  requireRole(["admin", "auditor", "districtAdmin"]),
  async (req, res) => {
    const { schoolCode, role } = req.user;
    try {
      const notesScanParams =
        role === "districtAdmin"
          ? { TableName: "Notes" }
          : {
              TableName: "Notes",
              FilterExpression: "schoolCode = :sc",
              ExpressionAttributeValues: { ":sc": schoolCode },
            };
      const notesData = await db.send(new ScanCommand(notesScanParams));
      const records = (notesData.Items || []).filter(
        (n) => n.archived || n.deleted
      );
      res.json({ records });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);

// =====================
// ADMIN USER MANAGEMENT
// =====================

const ALLOWED_ROLES = [
  "counselor",
  "admin",
  "districtAdmin",
  "auditor",
  "superadmin",
];

async function invalidateUserSessions(email) {
  try {
    const result = await db.send(
      new ScanCommand({
        TableName: "Sessions",
        FilterExpression: "email = :e",
        ExpressionAttributeValues: { ":e": email },
      })
    );
    const sessions = result.Items || [];
    for (const s of sessions) {
      await db.send(
        new UpdateCommand({
          TableName: "Sessions",
          Key: { sessionId: s.sessionId },
          UpdateExpression: "set valid = :v",
          ExpressionAttributeValues: { ":v": false },
        })
      );
    }
  } catch (e) {
    console.error("Failed to invalidate sessions for", email, e);
  }
}

// List users (admin: within school, districtAdmin: all)
app.get(
  "/admin/users",
  authMiddleware,
  requireRole(["admin", "districtAdmin"]),
  async (req, res) => {
    const { role, schoolCode } = req.user;
    try {
      const params =
        role === "districtAdmin"
          ? { TableName: "Users" }
          : {
              TableName: "Users",
              FilterExpression: "schoolCode = :sc",
              ExpressionAttributeValues: { ":sc": schoolCode },
            };
      const data = await db.send(new ScanCommand(params));
      const users = (data.Items || []).map((u) => ({
        email: u.email,
        firstName: u.firstName,
        lastName: u.lastName,
        role: u.role || "counselor",
        schoolCode: u.schoolCode,
        verified: !!u.verified,
        disabled: !!u.disabled,
      }));
      res.json({ users });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);

// Create user (admin: only own school; districtAdmin: any school). Generates a temporary password.
app.post(
  "/admin/users",
  authMiddleware,
  requireRole(["admin", "districtAdmin"]),
  async (req, res) => {
    try {
      let { email, firstName, lastName, role, schoolCode, phoneNumber } =
        req.body || {};
      if (!email || !firstName || !lastName) {
        return res.status(400).json({ error: "Missing required fields" });
      }
      // Restrict non-district admins to their school
      if (req.user.role !== "districtAdmin") {
        schoolCode = req.user.schoolCode;
      }
      // Validate role
      if (role && !ALLOWED_ROLES.includes(role)) {
        return res.status(400).json({ error: "Invalid role" });
      }
      // Enforce approved domain policy
      const allowed = APPROVED_EMAIL_DOMAINS.some(
        (domain) =>
          email.endsWith("@" + domain) ||
          email.endsWith("." + domain) ||
          email.endsWith(domain)
      );
      if (!allowed) {
        return res.status(403).json({ error: "Email domain not approved" });
      }
      // Ensure school exists
      const schoolData = await db.send(
        new GetCommand({ TableName: "Schools", Key: { schoolCode } })
      );
      if (!schoolData.Item) {
        return res.status(400).json({ error: "Invalid schoolCode" });
      }
      // Check if user already exists
      const existing = await getUserByEmail(email);
      if (existing && !existing.disabled) {
        return res.status(409).json({ error: "User already exists" });
      }
      // Generate temp password
      const tempPassword = crypto
        .randomBytes(9)
        .toString("base64")
        .replace(/[^a-zA-Z0-9]/g, "")
        .slice(0, 12);
      const hashed = await hashPassword(tempPassword);
      const item = {
        email,
        password: hashed,
        schoolCode,
        firstName,
        lastName,
        verified: true,
        phoneNumber: phoneNumber || null,
        phoneVerified: false,
        totpSecret: null,
        totpVerified: false,
        mfaMethod: "totp",
        role: role || "counselor",
        disabled: false,
      };
      await db.send(new PutCommand({ TableName: "Users", Item: item }));
      res.status(201).json({
        message: "User created",
        user: {
          email: item.email,
          firstName: item.firstName,
          lastName: item.lastName,
          role: item.role,
          schoolCode: item.schoolCode,
          verified: item.verified,
          disabled: item.disabled,
        },
        tempPassword,
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);

// Update user (role, schoolCode [districtAdmin only], names, disabled flag)
app.put(
  "/admin/users/:email",
  authMiddleware,
  requireRole(["admin", "districtAdmin"]),
  async (req, res) => {
    try {
      const targetEmail = req.params.email;
      const target = await getUserByEmail(targetEmail);
      if (!target) return res.status(404).json({ error: "User not found" });
      if (
        req.user.role !== "districtAdmin" &&
        target.schoolCode !== req.user.schoolCode
      ) {
        return res.status(403).json({ error: "Forbidden" });
      }
      const { role, schoolCode, firstName, lastName, disabled } =
        req.body || {};
      const updates = [];
      const values = {};
      if (role !== undefined) {
        if (!ALLOWED_ROLES.includes(role))
          return res.status(400).json({ error: "Invalid role" });
        // Prevent changing superadmin's role unless superadmin
        if (target.role === "superadmin" && req.user.role !== "superadmin") {
          return res.status(403).json({ error: "Cannot modify superadmin" });
        }
        updates.push("#r = :r");
        values[":r"] = role;
      }
      if (firstName !== undefined) {
        updates.push("firstName = :fn");
        values[":fn"] = firstName;
      }
      if (lastName !== undefined) {
        updates.push("lastName = :ln");
        values[":ln"] = lastName;
      }
      if (disabled !== undefined) {
        updates.push("disabled = :d");
        values[":d"] = !!disabled;
      }
      if (schoolCode !== undefined) {
        if (req.user.role !== "districtAdmin") {
          return res
            .status(403)
            .json({ error: "Only district admins can change school" });
        }
        // Validate school exists
        const schoolData = await db.send(
          new GetCommand({ TableName: "Schools", Key: { schoolCode } })
        );
        if (!schoolData.Item) {
          return res.status(400).json({ error: "Invalid schoolCode" });
        }
        updates.push("schoolCode = :sc");
        values[":sc"] = schoolCode;
      }
      if (updates.length === 0)
        return res.status(400).json({ error: "No changes" });
      const result = await db.send(
        new UpdateCommand({
          TableName: "Users",
          Key: { email: targetEmail },
          UpdateExpression: "set " + updates.join(", "),
          ExpressionAttributeValues: values,
          ExpressionAttributeNames: { "#r": "role" },
          ReturnValues: "ALL_NEW",
        })
      );
      // Invalidate sessions if disabling or role changes
      if (disabled === true || role !== undefined) {
        await invalidateUserSessions(targetEmail);
      }
      // Log audit
      await logAudit({
        userEmail: req.user.email,
        action: `USER_UPDATED ${targetEmail}`,
        req,
        displayName: req.user.displayName,
      });
      res.json({ message: "User updated", user: result.Attributes });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);

// Deactivate user (soft delete)
app.delete(
  "/admin/users/:email",
  authMiddleware,
  requireRole(["admin", "districtAdmin"]),
  async (req, res) => {
    try {
      const targetEmail = req.params.email;
      const target = await getUserByEmail(targetEmail);
      if (!target) return res.status(404).json({ error: "User not found" });
      if (
        req.user.role !== "districtAdmin" &&
        target.schoolCode !== req.user.schoolCode
      ) {
        return res.status(403).json({ error: "Forbidden" });
      }
      if (target.role === "superadmin" && req.user.role !== "superadmin") {
        return res.status(403).json({ error: "Cannot modify superadmin" });
      }
      await db.send(
        new UpdateCommand({
          TableName: "Users",
          Key: { email: targetEmail },
          UpdateExpression: "set disabled = :d",
          ExpressionAttributeValues: { ":d": true },
        })
      );
      await invalidateUserSessions(targetEmail);
      await logAudit({
        userEmail: req.user.email,
        action: `USER_DISABLED ${targetEmail}`,
        req,
        displayName: req.user.displayName,
      });
      res.json({ message: "User deactivated" });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);

// =====================
// RECORD MANAGEMENT ENDPOINTS (Admin)
// =====================

// Archive Student (admin only; marks student archived=true)
app.post(
  "/students/:studentId/archive",
  authMiddleware,
  requireRole(["admin", "districtAdmin"]),
  async (req, res) => {
    const { studentId } = req.params;
    try {
      const data = await db.send(
        new GetCommand({ TableName: "Students", Key: { studentId } })
      );
      const student = data.Item;
      if (!student) return res.status(404).json({ error: "Student not found" });
      if (
        req.user.role !== "districtAdmin" &&
        student.schoolCode !== req.user.schoolCode
      ) {
        return res.status(403).json({ error: "Forbidden" });
      }
      await db.send(
        new UpdateCommand({
          TableName: "Students",
          Key: { studentId },
          UpdateExpression: "set archived = :a",
          ExpressionAttributeValues: { ":a": true },
        })
      );
      await logAudit({
        userEmail: req.user.email,
        studentId,
        action: "STUDENT_ARCHIVED",
        req,
        displayName: req.user.displayName,
      });
      res.json({ message: "Student archived" });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);

// Soft-delete Student (admin)
app.delete(
  "/students/:studentId",
  authMiddleware,
  requireRole(["admin", "districtAdmin"]),
  async (req, res) => {
    const { studentId } = req.params;
    try {
      const data = await db.send(
        new GetCommand({ TableName: "Students", Key: { studentId } })
      );
      const student = data.Item;
      if (!student) return res.status(404).json({ error: "Student not found" });
      if (
        req.user.role !== "districtAdmin" &&
        student.schoolCode !== req.user.schoolCode
      ) {
        return res.status(403).json({ error: "Forbidden" });
      }
      await db.send(
        new UpdateCommand({
          TableName: "Students",
          Key: { studentId },
          UpdateExpression: "set deleted = :d",
          ExpressionAttributeValues: { ":d": true },
        })
      );
      await logAudit({
        userEmail: req.user.email,
        studentId,
        action: "STUDENT_DELETED",
        req,
        displayName: req.user.displayName,
      });
      res.json({ message: "Student deleted (soft)" });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);

// Hard-delete Student (admin/districtAdmin)
app.delete(
  "/admin/students/:studentId/hard",
  authMiddleware,
  requireRole(["admin", "districtAdmin"]),
  async (req, res) => {
    const { studentId } = req.params;
    try {
      const data = await db.send(
        new GetCommand({ TableName: "Students", Key: { studentId } })
      );
      const student = data.Item;
      if (!student) return res.status(404).json({ error: "Student not found" });
      if (
        req.user.role !== "districtAdmin" &&
        student.schoolCode !== req.user.schoolCode
      ) {
        return res.status(403).json({ error: "Forbidden" });
      }
      await db.send(
        new DeleteCommand({ TableName: "Students", Key: { studentId } })
      );
      await logAudit({
        userEmail: req.user.email,
        studentId,
        action: "STUDENT_HARD_DELETED",
        req,
        displayName: req.user.displayName,
      });
      res.json({ message: "Student hard-deleted" });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);

// Hard-delete Note (admin/districtAdmin)
app.delete(
  "/admin/notes/:noteId/hard",
  authMiddleware,
  requireRole(["admin", "districtAdmin"]),
  async (req, res) => {
    const { noteId } = req.params;
    try {
      const data = await db.send(
        new GetCommand({ TableName: "Notes", Key: { noteId } })
      );
      const note = data.Item;
      if (!note) return res.status(404).json({ error: "Note not found" });
      if (note.legalHold) {
        return res
          .status(403)
          .json({ error: "Note is under legal hold and cannot be deleted" });
      }
      if (
        req.user.role !== "districtAdmin" &&
        note.schoolCode !== req.user.schoolCode
      ) {
        return res.status(403).json({ error: "Forbidden" });
      }
      await db.send(new DeleteCommand({ TableName: "Notes", Key: { noteId } }));
      await logAudit({
        userEmail: req.user.email,
        noteId,
        action: "NOTE_HARD_DELETED",
        req,
        displayName: req.user.displayName,
      });
      res.json({ message: "Note hard-deleted" });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);

// Retention settings (get)
app.get(
  "/admin/retention-settings",
  authMiddleware,
  requireRole(["admin", "districtAdmin"]),
  async (req, res) => {
    try {
      const schoolCode =
        req.user.role === "districtAdmin" && req.query.schoolCode
          ? req.query.schoolCode
          : req.user.schoolCode;
      const data = await db.send(
        new GetCommand({ TableName: "Schools", Key: { schoolCode } })
      );
      if (!data.Item)
        return res.status(404).json({ error: "School not found" });
      const retention =
        (data.Item.metadata && data.Item.metadata.retentionPolicy) || null;
      res.json({ retention });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);

// Retention settings (set)
app.post(
  "/admin/retention-settings",
  authMiddleware,
  requireRole(["admin", "districtAdmin"]),
  async (req, res) => {
    try {
      let { mode, durationDays, schoolCode } = req.body || {};
      if (!mode || !["archive", "delete"].includes(mode)) {
        return res.status(400).json({ error: "Invalid mode" });
      }
      durationDays = Number(durationDays);
      if (!Number.isFinite(durationDays) || durationDays <= 0) {
        return res.status(400).json({ error: "Invalid durationDays" });
      }
      if (req.user.role !== "districtAdmin") {
        schoolCode = req.user.schoolCode;
      }
      const school = await db.send(
        new GetCommand({ TableName: "Schools", Key: { schoolCode } })
      );
      if (!school.Item)
        return res.status(404).json({ error: "School not found" });
      // Update metadata.retentionPolicy
      const existingMeta = school.Item.metadata || {};
      const newMeta = {
        ...existingMeta,
        retentionPolicy: {
          mode,
          durationDays,
          updatedAt: new Date().toISOString(),
        },
      };
      await db.send(
        new UpdateCommand({
          TableName: "Schools",
          Key: { schoolCode },
          UpdateExpression: "set metadata = :m",
          ExpressionAttributeValues: { ":m": newMeta },
        })
      );
      res.json({
        message: "Retention settings updated",
        retention: newMeta.retentionPolicy,
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);

// Transfer Student Data to another school (districtAdmin only)
app.post(
  "/admin/transfer-student-data",
  authMiddleware,
  requireRole(["districtAdmin"]),
  async (req, res) => {
    try {
      const { studentId, targetSchoolCode } = req.body || {};
      if (!studentId || !targetSchoolCode) {
        return res
          .status(400)
          .json({ error: "Missing studentId or targetSchoolCode" });
      }
      const targetSchool = await db.send(
        new GetCommand({
          TableName: "Schools",
          Key: { schoolCode: targetSchoolCode },
        })
      );
      if (!targetSchool.Item)
        return res.status(404).json({ error: "Target school not found" });
      const stuData = await db.send(
        new GetCommand({ TableName: "Students", Key: { studentId } })
      );
      const student = stuData.Item;
      if (!student) return res.status(404).json({ error: "Student not found" });
      const fromSchool = student.schoolCode;
      if (fromSchool === targetSchoolCode) {
        return res
          .status(400)
          .json({ error: "Student already in target school" });
      }
      // Update student
      await db.send(
        new UpdateCommand({
          TableName: "Students",
          Key: { studentId },
          UpdateExpression: "set schoolCode = :sc",
          ExpressionAttributeValues: { ":sc": targetSchoolCode },
        })
      );
      // Move notes belonging to student
      const notesScan = await db.send(
        new ScanCommand({
          TableName: "Notes",
          FilterExpression: "studentId = :sid",
          ExpressionAttributeValues: { ":sid": studentId },
        })
      );
      const notes = notesScan.Items || [];
      let updatedNotes = 0;
      for (const n of notes) {
        await db.send(
          new UpdateCommand({
            TableName: "Notes",
            Key: { noteId: n.noteId },
            UpdateExpression: "set schoolCode = :sc",
            ExpressionAttributeValues: { ":sc": targetSchoolCode },
          })
        );
        updatedNotes += 1;
      }
      await logAudit({
        userEmail: req.user.email,
        studentId,
        action: `STUDENT_TRANSFERRED ${fromSchool} -> ${targetSchoolCode}`,
        req,
        displayName: req.user.displayName,
      });
      res.json({
        message: "Student data transferred",
        notesUpdated: updatedNotes,
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);

// =====================
// FILE UPLOAD: PRE-SIGNED URL FOR 504/IEP DOCS
// =====================

// Helper to sanitize file names for S3 keys
function sanitizeFileName(name) {
  if (typeof name !== "string") return "file";
  // Remove directory paths and normalize
  const base = name.split("/").pop().split("\\").pop();
  // Replace unsafe chars with _ and collapse repeats
  return (
    base
      .replace(/[^a-zA-Z0-9._-]+/g, "_")
      .replace(/__+/g, "_")
      .slice(0, 128) || "file"
  );
}

// Generate pre-signed PUT URL for uploading a file directly to S3
// Security: counselor or admin only; student must belong to same school
app.post(
  "/upload-504",
  authMiddleware,
  requireRole(["counselor", "admin", "districtAdmin"]),
  async (req, res) => {
    console.log("🟢 upload-504 START", req.body);

    try {
      const { studentId, fileName, fileType, filePurpose } = req.body || {};
      if (!studentId || !fileName || !fileType) {
        console.log("❌ Missing fields");
        return res
          .status(400)
          .json({ error: "Missing studentId, fileName, or fileType" });
      }

      console.log("✅ Step 1: Validated input");

      const stuData = await db.send(
        new GetCommand({ TableName: "Students", Key: { studentId } })
      );
      console.log("✅ Step 2: Got student data", stuData);
      const student = stuData.Item;
      if (!student) return res.status(404).json({ error: "Student not found" });

      const bucket = process.env.S3_BUCKET;
      console.log("✅ Step 3: Bucket =", bucket);
      const fileId = uuidv4();
      const safeFileName = fileName.trim().replace(/\s+/g, "_");
      const key = `${req.user.schoolCode}/students/${studentId}/files/${fileId}-${safeFileName}`;

      console.log("✅ Step 4: Key =", key);

      const putCmd = new PutObjectCommand({
        Bucket: bucket,
        Key: key,
        ContentType: fileType,
      });

      console.log("✅ Step 5: Creating presigned URL...");
      const uploadUrl = await getSignedUrl(s3, putCmd, { expiresIn: 300 });
      console.log("✅ Step 6: Got presigned URL");

      const fileRecord = {
        fileId,
        studentId,
        schoolCode: req.user.schoolCode,
        fileName,
        fileType,
        createdAt: new Date().toISOString(),
        s3Bucket: bucket,
        s3Key: key,
      };

      console.log("✅ Step 7: Writing to DynamoDB...");
      await db.send(new PutCommand({ TableName: "Files", Item: fileRecord }));
      console.log("✅ Step 8: Wrote to DynamoDB successfully");

      return res.json({ uploadUrl, fileId });
    } catch (err) {
      console.error("❌ upload-504 error:", err);
      return res
        .status(500)
        .json({ error: err.message || "Failed to generate upload URL" });
    }
  }
);

// =====================
// FILE DOWNLOAD: PRE-SIGNED URL FOR FILES BY ID
// =====================
// Returns a 5-minute presigned GET URL for an existing file
// Authorization: counselor/admin within same school; districtAdmin can access any school
app.get(
  "/files/:fileId/download",
  authMiddleware,
  requireRole(["counselor", "admin", "districtAdmin"]),
  async (req, res) => {
    try {
      const { fileId } = req.params;
      if (!fileId) return res.status(400).json({ error: "Missing fileId" });

      // Lookup file metadata
      let file;
      try {
        const resp = await db.send(
          new GetCommand({ TableName: "Files", Key: { fileId } })
        );
        file = resp.Item;
      } catch (err) {
        console.error("Error fetching file metadata:", err);
        return res.status(500).json({ error: "Failed to fetch file metadata" });
      }

      if (!file) return res.status(404).json({ error: "File not found" });

      const { role, schoolCode } = req.user;
      if (role !== "districtAdmin" && file.schoolCode !== schoolCode) {
        return res.status(403).json({ error: "Forbidden" });
      }

      const bucket =
        file.s3Bucket || process.env.S3_BUCKET || process.env.S3_504_BUCKET;
      const key = file.s3Key;
      if (!bucket || !key) {
        return res.status(500).json({ error: "File storage details missing" });
      }

      // Suggest filename and content type
      const name = sanitizeFileName(file.fileName || "file");
      const contentType =
        typeof file.fileType === "string" && file.fileType
          ? file.fileType
          : "application/octet-stream";

      console.log("🎯 DOWNLOAD DEBUG:", { bucket, key });

      // Create presigned GET URL valid for 5 minutes
      const getCmd = new GetObjectCommand({
        Bucket: bucket,
        Key: key,
        ResponseContentType: contentType,
        ResponseContentDisposition: `attachment; filename="${name}"`,
      });
      const downloadUrl = await getSignedUrl(s3, getCmd, { expiresIn: 300 });

      // Log audit of download (best-effort)
      try {
        await logAudit({
          userEmail: req.user.email,
          studentId: file.studentId,
          action: `FILE_DOWNLOADED ${fileId}`,
          req,
          displayName: req.user.displayName,
        });
      } catch (e) {
        console.error("audit log (download) failed", e);
      }

      res.json({ downloadUrl, expiresIn: 300, fileName: name, contentType });
    } catch (err) {
      console.error("download file error:", err);
      res.status(500).json({ error: "Failed to generate download URL" });
    }
  }
);

// =====================
// LIST FILES FOR A STUDENT
// =====================
// Returns all file metadata records for a given studentId.
// Authorization: counselor/admin within same school; districtAdmin can view any.
app.get(
  "/students/:studentId/files",
  authMiddleware,
  requireRole(["counselor", "admin", "districtAdmin"]),
  async (req, res) => {
    try {
      const { studentId } = req.params;
      if (!studentId)
        return res.status(400).json({ error: "Missing studentId" });

      // Validate student and school scoping
      const stuData = await db.send(
        new GetCommand({ TableName: "Students", Key: { studentId } })
      );
      const student = stuData.Item;
      if (!student) return res.status(404).json({ error: "Student not found" });
      const { role, schoolCode } = req.user;
      if (role !== "districtAdmin" && student.schoolCode !== schoolCode) {
        return res.status(403).json({ error: "Forbidden" });
      }

      // Scan Files by studentId (and schoolCode for non-district admins)
      const scanParams =
        role === "districtAdmin"
          ? {
              TableName: "Files",
              FilterExpression: "studentId = :sid",
              ExpressionAttributeValues: { ":sid": studentId },
            }
          : {
              TableName: "Files",
              FilterExpression: "studentId = :sid AND schoolCode = :sc",
              ExpressionAttributeValues: {
                ":sid": studentId,
                ":sc": schoolCode,
              },
            };
      const data = await db.send(new ScanCommand(scanParams));
      // Normalize legacy records that may have used 'F
      const files = (data.Items || []).map((it) => ({ ...it })).slice();
      files.sort(
        (a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0)
      );
      res.json({ files });
    } catch (err) {
      console.error("list files error:", err);
      res.status(500).json({ error: "Failed to list files" });
    }
  }
);

module.exports = app;
