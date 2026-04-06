require("dotenv").config();

const express = require("express");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const { v4: uuidv4 } = require("uuid");
const cors = require("cors");
const session = require("express-session");
const fs = require("fs");
const multer = require("multer");
const os = require("os");
const path = require("path");
const { initDb, query } = require("./db");

const app = express();

const PORT = Number(process.env.PORT) || 5000;
const uploadsBaseDir = process.env.VERCEL ? os.tmpdir() : __dirname;
const uploadsDir = path.join(uploadsBaseDir, "uploads");
const EMAIL_OTP_TTL_MS = 10 * 60 * 1000;
const EMAIL_OTP_MAX_ATTEMPTS = 5;
const isProduction = process.env.NODE_ENV === "production";
let appReadyPromise;

if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

function getAllowedOrigins() {
  const configuredOrigins = [
    process.env.FRONTEND_ORIGIN,
    process.env.FRONTEND_URL,
    process.env.CLIENT_URL,
    "http://localhost:3000",
  ]
    .flatMap((value) => String(value || "").split(","))
    .map((value) => value.trim())
    .filter(Boolean);

  if (process.env.VERCEL_URL) {
    configuredOrigins.push(`https://${process.env.VERCEL_URL}`);
  }

  return new Set(configuredOrigins);
}

const allowedOrigins = getAllowedOrigins();
const allowedOriginPatterns = [
  /^http:\/\/localhost(?::\d+)?$/i,
  /^https:\/\/[a-z0-9-]+\.vercel\.app$/i,
];

const corsOptions = {
  origin(origin, callback) {
    if (!origin) {
      callback(null, true);
      return;
    }

    if (
      allowedOrigins.has(origin) ||
      allowedOriginPatterns.some((pattern) => pattern.test(origin))
    ) {
      callback(null, true);
      return;
    }

    callback(new Error(`CORS blocked for origin: ${origin}`));
  },
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"],
  credentials: true,
};

const documentStorage = multer.diskStorage({
  destination(req, file, cb) {
    cb(null, uploadsDir);
  },
  filename(req, file, cb) {
    cb(null, `${file.fieldname}_${file.originalname}`);
  },
});

const documentUploadMany = multer({ storage: documentStorage }).array("image", 10);
const imageUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter(req, file, cb) {
    if (file?.mimetype?.startsWith("image/")) {
      cb(null, true);
      return;
    }

    cb(new Error("Only image uploads are allowed."));
  },
}).single("image");

const USER_PUBLIC_SELECT = `
  id AS _id,
  name,
  email,
  mobile,
  CAST(is_admin AS UNSIGNED) AS isAdmin,
  person_uuid AS personId,
  role
`;

const USER_AUTH_SELECT = `
  ${USER_PUBLIC_SELECT},
  password,
  reset_password_token AS resetPasswordToken,
  reset_password_expires AS resetPasswordExpires
`;

const DOCUMENT_SELECT = `
  id AS _id,
  object_id AS objectId,
  name,
  doc
`;

const FLAT_SELECT = `
  id AS _id,
  flatlocation,
  pricing,
  rating,
  sqtfoot,
  bedroom,
  beds,
  imagesq,
  person_id AS personId,
  name,
  email,
  conte
`;

const NEWS_SELECT = `
  id AS _id,
  heading,
  images,
  newsdiscription,
  date,
  link_url AS Link
`;

const CONTACT_SELECT = `
  id AS _id,
  emailid,
  subject,
  message
`;

const QUERY_SELECT = `
  id AS _id,
  name,
  flatno,
  mobileno,
  service
`;

app.use(cors(corsOptions));
app.use(express.json());
app.use(
  session({
    secret: process.env.SESSION_SECRET || "yourSecretKey",
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: isProduction,
      sameSite: isProduction ? "none" : "lax",
    },
  })
);
app.use("/documents", express.static(uploadsDir));

function normalizeBoolean(value) {
  return value === true || value === "true" || value === 1 || value === "1";
}

function toNullableInt(value) {
  if (value === undefined || value === null || value === "") {
    return null;
  }

  const parsed = Number.parseInt(value, 10);
  return Number.isNaN(parsed) ? null : parsed;
}

function toNullableFloat(value) {
  if (value === undefined || value === null || value === "") {
    return null;
  }

  const parsed = Number.parseFloat(value);
  return Number.isNaN(parsed) ? null : parsed;
}

function getCloudinaryConfig() {
  const cloudName = process.env.CLOUDINARY_CLOUD_NAME;
  const apiKey = process.env.CLOUDINARY_API_KEY;
  const apiSecret = process.env.CLOUDINARY_API_SECRET;

  if (!cloudName || !apiKey || !apiSecret) {
    throw new Error(
      "Cloudinary credentials are missing. Set CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY, and CLOUDINARY_API_SECRET."
    );
  }

  return { cloudName, apiKey, apiSecret };
}

function getMailerConfig() {
  const user = process.env.SMTP_USER || process.env.EMAIL;
  const pass = process.env.SMTP_PASS || process.env.EMAIL_PASS;
  const from = process.env.MAIL_FROM || user;

  if (!user || !pass) {
    throw new Error(
      "SMTP credentials are missing. Set SMTP_USER, SMTP_PASS, and MAIL_FROM."
    );
  }

  return { user, pass, from };
}

function getRazorpayConfig() {
  const keyId = String(process.env.RAZORPAY_KEY_ID || "").trim();
  const keySecret = String(process.env.RAZORPAY_KEY_SECRET || "").trim();

  if (!keyId || !keySecret) {
    throw new Error(
      "Razorpay credentials are missing. Set RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET."
    );
  }

  return { keyId, keySecret };
}

function normalizeEmailAddress(email) {
  return String(email || "").trim().toLowerCase();
}

function createCloudinarySignature(params, apiSecret) {
  const serializedParams = Object.keys(params)
    .filter((key) => params[key] !== undefined && params[key] !== null && params[key] !== "")
    .sort()
    .map((key) => `${key}=${params[key]}`)
    .join("&");

  return crypto
    .createHash("sha1")
    .update(`${serializedParams}${apiSecret}`)
    .digest("hex");
}

async function uploadImageToCloudinary(file, folder) {
  if (!file?.buffer) {
    throw new Error("Image buffer is missing.");
  }

  const { cloudName, apiKey, apiSecret } = getCloudinaryConfig();
  const timestamp = Math.floor(Date.now() / 1000);
  const signature = createCloudinarySignature({ folder, timestamp }, apiSecret);
  const formData = new FormData();

  formData.append(
    "file",
    new Blob([file.buffer], { type: file.mimetype || "application/octet-stream" }),
    file.originalname || `upload-${Date.now()}`
  );
  formData.append("api_key", apiKey);
  formData.append("timestamp", String(timestamp));
  formData.append("signature", signature);

  if (folder) {
    formData.append("folder", folder);
  }

  const response = await fetch(
    `https://api.cloudinary.com/v1_1/${cloudName}/image/upload`,
    {
      method: "POST",
      body: formData,
    }
  );

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Cloudinary upload failed (${response.status}): ${errorText}`);
  }

  const payload = await response.json();
  return payload.secure_url || payload.url;
}

function getOtpCodeHash(code) {
  return crypto.createHash("sha256").update(String(code)).digest("hex");
}

function createOtpCode() {
  return String(Math.floor(1000 + Math.random() * 9000));
}

async function cleanupExpiredEmailVerifications() {
  await query("DELETE FROM email_verifications WHERE expires_at <= ?", [Date.now()]);
}

function createEmailTransporter() {
  const { user, pass, from } = getMailerConfig();

  return {
    from,
    transporter: nodemailer.createTransport({
      service: "gmail",
      auth: {
        user,
        pass,
      },
    }),
  };
}

async function sendEmailOtp({ email, code, purpose }) {
  const { from, transporter } = createEmailTransporter();
  const subject =
    purpose === "register"
      ? "Your registration verification code"
      : "Your login verification code";

  await transporter.sendMail({
    from,
    to: email,
    subject,
    text: `Your ${purpose} verification code is ${code}. It will expire in 10 minutes.`,
    html: `
      <div style="font-family: Arial, sans-serif; color: #111827; line-height: 1.6;">
        <h2 style="margin-bottom: 8px;">Email Verification Code</h2>
        <p>Use the following 4-digit code to complete your ${purpose}:</p>
        <p style="font-size: 28px; font-weight: 700; letter-spacing: 8px; margin: 16px 0;">${code}</p>
        <p>This code will expire in 10 minutes.</p>
      </div>
    `,
  });
}

async function createPendingEmailVerification({ email, purpose, payload }) {
  await cleanupExpiredEmailVerifications();

  const verificationId = uuidv4();
  const code = createOtpCode();
  const codeHash = getOtpCodeHash(code);
  const expiresAt = Date.now() + EMAIL_OTP_TTL_MS;

  await query(
    `
      INSERT INTO email_verifications (
        id,
        purpose,
        email,
        code_hash,
        payload_json,
        expires_at,
        attempts_left
      )
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `,
    [
      verificationId,
      purpose,
      normalizeEmailAddress(email),
      codeHash,
      JSON.stringify(payload),
      expiresAt,
      EMAIL_OTP_MAX_ATTEMPTS,
    ]
  );

  try {
    await sendEmailOtp({
      email,
      code,
      purpose,
    });
  } catch (error) {
    await query("DELETE FROM email_verifications WHERE id = ?", [verificationId]);
    throw error;
  }

  return verificationId;
}

async function consumePendingEmailVerification({ verificationId, otp, purpose }) {
  await cleanupExpiredEmailVerifications();

  const rows = await query(
    `
      SELECT
        id,
        purpose,
        email,
        code_hash AS codeHash,
        payload_json AS payloadJson,
        expires_at AS expiresAt,
        attempts_left AS attemptsLeft
      FROM email_verifications
      WHERE id = ?
      LIMIT 1
    `,
    [verificationId]
  );

  const verification = rows[0];

  if (!verification || verification.purpose !== purpose) {
    throw new Error("Verification request not found. Please request a new code.");
  }

  if (verification.expiresAt <= Date.now()) {
    await query("DELETE FROM email_verifications WHERE id = ?", [verificationId]);
    throw new Error("Verification code expired. Please request a new code.");
  }

  const otpHash = getOtpCodeHash(String(otp || "").trim());
  if (otpHash !== verification.codeHash) {
    const attemptsLeft = verification.attemptsLeft - 1;

    if (attemptsLeft <= 0) {
      await query("DELETE FROM email_verifications WHERE id = ?", [verificationId]);
      throw new Error("Too many incorrect attempts. Please request a new code.");
    }

    await query(
      "UPDATE email_verifications SET attempts_left = ? WHERE id = ?",
      [attemptsLeft, verificationId]
    );

    throw new Error(
      `Invalid verification code. ${attemptsLeft} attempt(s) left.`
    );
  }

  await query("DELETE FROM email_verifications WHERE id = ?", [verificationId]);

  let payload;

  try {
    payload = JSON.parse(verification.payloadJson);
  } catch (error) {
    throw new Error("Verification data is invalid. Please request a new code.");
  }

  return {
    ...verification,
    payload,
  };
}

function toAmountInSubunits(value) {
  const parsed = Number(value);

  if (!Number.isFinite(parsed) || parsed < 0) {
    return null;
  }

  return Math.round(parsed * 100);
}

async function createRazorpayOrder({ amount, currency = "INR", receipt, notes }) {
  const { keyId, keySecret } = getRazorpayConfig();
  const authorization = Buffer.from(`${keyId}:${keySecret}`).toString("base64");

  const response = await fetch("https://api.razorpay.com/v1/orders", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Basic ${authorization}`,
    },
    body: JSON.stringify({
      amount,
      currency,
      receipt,
      notes,
    }),
  });

  if (!response.ok) {
    const errorText = await response.text();

    if (response.status === 401) {
      throw new Error(
        "Razorpay authentication failed. Verify the exact test Key ID and Key Secret from your Razorpay dashboard."
      );
    }

    throw new Error(
      `Razorpay order creation failed (${response.status}): ${errorText}`
    );
  }

  const order = await response.json();
  return { keyId, order };
}

function mapUser(row) {
  if (!row) {
    return row;
  }

  const normalizedRole =
    typeof row.role === "string" ? row.role.trim().toLowerCase() : row.role;

  return {
    ...row,
    role: normalizedRole,
    isAdmin: Boolean(row.isAdmin) || normalizedRole === "admin",
  };
}

function mapUsers(rows) {
  return rows.map(mapUser);
}

function buildLoginResponse(user) {
  return {
    message:
      user.isAdmin || user.role === "admin"
        ? "Hello admin. User logged in successfully"
        : user.role === "tenant"
          ? "Hello tenant. User logged in successfully"
          : "Hello user. User logged in successfully",
    user: {
      _id: user._id,
      name: user.name,
      email: user.email,
      mobile: user.mobile,
      role: user.role,
      isAdmin: user.isAdmin,
      personId: user.personId,
    },
  };
}

function groupByObjectId(docs) {
  return docs.reduce((grouped, doc) => {
    if (!grouped[doc.objectId]) {
      grouped[doc.objectId] = [];
    }

    grouped[doc.objectId].push(doc);
    return grouped;
  }, {});
}

async function getUserByEmail(email, includeAuthFields = false) {
  const selectClause = includeAuthFields ? USER_AUTH_SELECT : USER_PUBLIC_SELECT;
  const rows = await query(
    `SELECT ${selectClause} FROM users WHERE LOWER(email) = ? LIMIT 1`,
    [normalizeEmailAddress(email)]
  );

  return mapUser(rows[0]);
}

async function getUserById(userId, includeAuthFields = false) {
  const selectClause = includeAuthFields ? USER_AUTH_SELECT : USER_PUBLIC_SELECT;
  const rows = await query(
    `SELECT ${selectClause} FROM users WHERE id = ? LIMIT 1`,
    [userId]
  );

  return mapUser(rows[0]);
}

app.post("/login/api/check", async (req, res) => {
  try {
    const { email, password, verificationId, otp } = req.body;

    if (verificationId || otp) {
      const verification = await consumePendingEmailVerification({
        verificationId,
        otp,
        purpose: "login",
      });
      const verifiedUser = await getUserById(verification.payload.userId, true);

      if (!verifiedUser) {
        return res
          .status(404)
          .json({ error: "User not found. Please try logging in again." });
      }

      return res.status(200).json(buildLoginResponse(verifiedUser));
    }

    if (!email || !password) {
      return res
        .status(400)
        .json({ error: "Email and password are required." });
    }

    const normalizedEmail = normalizeEmailAddress(email);
    const user = await getUserByEmail(normalizedEmail, true);

    if (!user) {
      return res
        .status(401)
        .json({ message: "Authentication failed. User not found." });
    }

    const isPasswordValid = await bcrypt.compare(password || "", user.password);

    if (!isPasswordValid) {
      return res
        .status(401)
        .json({ message: "Authentication failed. Incorrect password." });
    }

    const createdVerificationId = await createPendingEmailVerification({
      email: user.email,
      purpose: "login",
      payload: {
        userId: user._id,
      },
    });

    res.status(200).json({
      requiresVerification: true,
      verificationId: createdVerificationId,
      message: "Verification code sent to your email.",
    });
  } catch (error) {
    console.error("Error during login:", error);
    const statusCode =
      error.message &&
      /Verification request not found|Verification code expired|Invalid verification code|Too many incorrect attempts/.test(
        error.message
      )
        ? 400
        : 500;

    res.status(statusCode).json({ error: error.message || "Internal Server Error" });
  }
});

app.post("/submitcontectus", async (req, res) => {
  try {
    const { emailid, subject, message } = req.body;

    await query(
      "INSERT INTO contact_messages (emailid, subject, message) VALUES (?, ?, ?)",
      [emailid, subject, message]
    );

    res
      .status(201)
      .json({ message: "User Contect detail submit successfully" });
  } catch (error) {
    console.error("Error during user Contect detail submit:", error);
    res.status(400).json({ error: error.message });
  }
});

app.post("/uploaddocuments/:id", documentUploadMany, async (req, res) => {
  try {
    const files = req.files;
    const objectId = req.params.id;
    const name = req.body.name;

    if (!files || files.length === 0) {
      return res.status(400).json({ error: "No files uploaded" });
    }

    const savedDocuments = [];
    for (const file of files) {
      const result = await query(
        "INSERT INTO documents (object_id, name, doc) VALUES (?, ?, ?)",
        [objectId, name, file.filename]
      );

      savedDocuments.push({
        _id: result.insertId,
        objectId,
        name,
        doc: file.filename,
      });
    }

    res.json({
      message: "Documents uploaded successfully",
      documents: savedDocuments,
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.get("/getdocument", async (req, res) => {
  try {
    const allDocs = await query(`SELECT ${DOCUMENT_SELECT} FROM documents`);

    if (!allDocs.length) {
      return res.status(404).json({ message: "No documents found" });
    }

    res.json({ documents: groupByObjectId(allDocs) });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete("/deleteflate/:id", async (req, res) => {
  try {
    await query("DELETE FROM rental_flats WHERE id = ?", [req.params.id]);
    res.json({ message: "successfully deleted" });
  } catch (error) {
    console.error(error);
    res.json({ message: error.message });
  }
});

app.get("/alldocuments", async (req, res) => {
  try {
    const allDocuments = await query(`SELECT ${DOCUMENT_SELECT} FROM documents`);
    res.json(allDocuments);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/newsupload", imageUpload, async (req, res) => {
  try {
    const { heading, date } = req.body;
    const newsdiscription =
      req.body.newsdiscription || req.body.newsDescription || "";
    const Link = req.body.Link || req.body.link || null;
    const image = req.file
      ? await uploadImageToCloudinary(req.file, "real-estate/news")
      : null;

    if (!image) {
      return res.status(400).json({ error: "Image is required" });
    }

    const result = await query(
      `
        INSERT INTO news (heading, images, newsdiscription, date, link_url)
        VALUES (?, ?, ?, ?, ?)
      `,
      [heading, image, newsdiscription, date || null, Link || null]
    );

    res.json({
      message: "news upload successfully",
      uploadnewsmodel: {
        _id: result.insertId,
        heading,
        date: date || null,
        Link: Link || null,
        newsdiscription,
        images: image,
      },
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.get("/allnews", async (req, res) => {
  try {
    const news = await query(`SELECT ${NEWS_SELECT} FROM news ORDER BY id DESC`);
    res.json(news);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/allcontectus", async (req, res) => {
  try {
    const contacts = await query(
      `SELECT ${CONTACT_SELECT} FROM contact_messages ORDER BY id DESC`
    );
    res.json(contacts);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete("/deleteNews/:id", async (req, res) => {
  try {
    await query("DELETE FROM news WHERE id = ?", [req.params.id]);
    res.json({ message: "successfully deleted" });
  } catch (error) {
    console.error(error);
    res.json({ message: error.message });
  }
});

app.delete("/deletecontect/:id", async (req, res) => {
  try {
    await query("DELETE FROM contact_messages WHERE id = ?", [req.params.id]);
    res.json({ message: "successfully deleted" });
  } catch (error) {
    console.error(error);
    res.json({ message: error.message });
  }
});

app.post("/uploadflat/:personId", imageUpload, async (req, res) => {
  try {
    const {
      flatlocation,
      pricing,
      rating,
      sqtfoot,
      bedroom,
      beds,
      name,
      email,
      conte,
    } = req.body;
    const image = req.file
      ? await uploadImageToCloudinary(req.file, "real-estate/flats")
      : null;
    const personId = req.params.personId;

    if (!image) {
      return res.status(400).json({ error: "Image is required" });
    }

    const user = await getUserById(personId);
    if (!user) {
      return res.status(404).json({ error: "Person not found" });
    }

    const result = await query(
      `
        INSERT INTO rental_flats (
          flatlocation,
          pricing,
          rating,
          sqtfoot,
          bedroom,
          beds,
          imagesq,
          person_id,
          name,
          email,
          conte
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `,
      [
        flatlocation,
        pricing,
        toNullableFloat(rating),
        toNullableInt(sqtfoot),
        toNullableInt(bedroom),
        toNullableInt(beds),
        image,
        String(personId),
        name,
        email,
        conte,
      ]
    );

    res.json({
      message: "Flat uploaded successfully",
      flat: {
        _id: result.insertId,
        flatlocation,
        pricing,
        rating: toNullableFloat(rating),
        sqtfoot: toNullableInt(sqtfoot),
        bedroom: toNullableInt(bedroom),
        beds: toNullableInt(beds),
        imagesq: image,
        personId: String(personId),
        name,
        email,
        conte,
      },
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.get("/images/:personId", async (req, res) => {
  try {
    const images = await query(
      `SELECT ${FLAT_SELECT} FROM rental_flats WHERE person_id = ? ORDER BY id DESC`,
      [req.params.personId]
    );

    if (!images.length) {
      return res
        .status(404)
        .json({ error: "No images found for the provided personId" });
    }

    res.json(images);
  } catch (error) {
    console.error("Error fetching images:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/user/:personId", async (req, res) => {
  try {
    const user = await getUserById(req.params.personId);

    if (!user) {
      return res
        .status(404)
        .json({ error: "User not found for the provided personId" });
    }

    res.json(user);
  } catch (error) {
    console.error("Error fetching user information:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/logout", (req, res) => {
  if (!req.session) {
    return res.status(200).json({ message: "No active session" });
  }

  req.session.destroy((error) => {
    if (error) {
      return res.status(500).json({ message: "Failed to log out" });
    }

    return res.status(200).json({ message: "Logged out successfully" });
  });
});

app.get("/persons/:id", async (req, res) => {
  try {
    const rows = await query(
      `SELECT ${FLAT_SELECT} FROM rental_flats WHERE id = ? LIMIT 1`,
      [req.params.id]
    );

    if (!rows.length) {
      return res.status(404).json({ error: "Person not found" });
    }

    res.json(rows[0]);
  } catch (error) {
    console.error("Error fetching person:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.post("/payments/create-order", async (req, res) => {
  try {
    const { flatId, amount = 0, currency = "INR" } = req.body;
    const normalizedFlatId = toNullableInt(flatId);

    if (!normalizedFlatId) {
      return res.status(400).json({ error: "A valid flatId is required." });
    }

    const flatRows = await query(
      `SELECT ${FLAT_SELECT} FROM rental_flats WHERE id = ? LIMIT 1`,
      [normalizedFlatId]
    );

    if (!flatRows.length) {
      return res.status(404).json({ error: "Flat not found." });
    }

    const flat = flatRows[0];
    const amountInSubunits = toAmountInSubunits(amount);

    if (amountInSubunits === null) {
      return res
        .status(400)
        .json({ error: "Amount must be a non-negative number." });
    }

    if (amountInSubunits === 0) {
      return res.json({
        free: true,
        amount: 0,
        currency,
        keyId: process.env.RAZORPAY_KEY_ID || null,
        booking: {
          flatId: flat._id,
          flatlocation: flat.flatlocation,
        },
        message: "Zero-amount booking confirmed without payment collection.",
      });
    }

    if (amountInSubunits < 100) {
      return res.status(400).json({
        error:
          "Razorpay requires the order amount to be at least INR 1.00.",
      });
    }

    const { keyId, order } = await createRazorpayOrder({
      amount: amountInSubunits,
      currency,
      receipt: `flat_${flat._id}_${Date.now()}`.slice(0, 40),
      notes: {
        flatId: String(flat._id),
        flatLocation: String(flat.flatlocation || ""),
      },
    });

    res.json({
      free: false,
      keyId,
      order,
      booking: {
        flatId: flat._id,
        flatlocation: flat.flatlocation,
      },
    });
  } catch (error) {
    console.error("Error creating Razorpay order:", error);
    res.status(500).json({ error: error.message || "Unable to create order." });
  }
});

app.post("/payments/verify", (req, res) => {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } =
      req.body;

    if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
      return res.status(400).json({
        success: false,
        message: "Payment verification details are incomplete.",
      });
    }

    const { keySecret } = getRazorpayConfig();
    const generatedSignature = crypto
      .createHmac("sha256", keySecret)
      .update(`${razorpay_order_id}|${razorpay_payment_id}`)
      .digest("hex");

    const providedSignatureBuffer = Buffer.from(razorpay_signature, "utf8");
    const generatedSignatureBuffer = Buffer.from(generatedSignature, "utf8");
    const signatureMatches =
      providedSignatureBuffer.length === generatedSignatureBuffer.length &&
      crypto.timingSafeEqual(
        providedSignatureBuffer,
        generatedSignatureBuffer
      );

    if (!signatureMatches) {
      return res.status(400).json({
        success: false,
        message: "Payment verification failed.",
      });
    }

    res.json({
      success: true,
      message: "Payment verified successfully.",
    });
  } catch (error) {
    console.error("Error verifying Razorpay payment:", error);
    res.status(500).json({
      success: false,
      message: error.message || "Unable to verify payment.",
    });
  }
});

app.post("/register", async (req, res) => {
  try {
    const { name, email, password, mobile, isAdmin, role, verificationId, otp } =
      req.body;

    if (verificationId || otp) {
      const verification = await consumePendingEmailVerification({
        verificationId,
        otp,
        purpose: "register",
      });
      const {
        name: pendingName,
        email: pendingEmail,
        hashedPassword,
        mobile: pendingMobile,
        isAdmin: pendingIsAdmin,
        role: pendingRole,
        personId,
      } = verification.payload;

      const existingUser = await getUserByEmail(pendingEmail);
      if (existingUser) {
        return res
          .status(409)
          .json({ error: "User with this email already exists" });
      }

      const result = await query(
        `
          INSERT INTO users (name, email, password, mobile, is_admin, person_uuid, role)
          VALUES (?, ?, ?, ?, ?, ?, ?)
        `,
        [
          pendingName,
          pendingEmail,
          hashedPassword,
          pendingMobile,
          normalizeBoolean(pendingIsAdmin) ? 1 : 0,
          personId,
          pendingRole || "user",
        ]
      );

      return res.status(201).json({
        message: "User registered successfully",
        userId: result.insertId,
        personId,
      });
    }

    if (!name || !email || !password || !mobile || !role) {
      return res.status(400).json({ error: "All fields are required." });
    }

    const normalizedEmail = normalizeEmailAddress(email);
    const existingUser = await getUserByEmail(normalizedEmail);
    if (existingUser) {
      return res
        .status(409)
        .json({ error: "User with this email already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const personId = uuidv4();
    const createdVerificationId = await createPendingEmailVerification({
      email: normalizedEmail,
      purpose: "register",
      payload: {
        name,
        email: normalizedEmail,
        hashedPassword,
        mobile,
        isAdmin: normalizeBoolean(isAdmin),
        role: role || "user",
        personId,
      },
    });

    res.status(200).json({
      requiresVerification: true,
      verificationId: createdVerificationId,
      message: "Verification code sent to your email.",
    });
  } catch (error) {
    console.error("Error during user registration:", error);
    res.status(400).json({ error: error.message });
  }
});

app.post("/forget/api/pswforget", async (req, res) => {
  const { email, resetToken, newPassword } = req.body;

  try {
    const user = await getUserByEmail(email, true);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    if (resetToken && user.resetPasswordToken) {
      const tokenExpired =
        user.resetPasswordExpires &&
        Number(user.resetPasswordExpires) < Date.now();

      if (user.resetPasswordToken !== resetToken || tokenExpired) {
        return res.status(400).json({ error: "Invalid or expired reset token" });
      }
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await query(
      `
        UPDATE users
        SET password = ?, reset_password_token = NULL, reset_password_expires = NULL
        WHERE id = ?
      `,
      [hashedPassword, user._id]
    );

    res.status(200).json({ message: "Password reset successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/finduser/api/finduser", async (req, res) => {
  const email = req.query.email || req.body?.email;

  try {
    if (!email) {
      return res.status(400).json({ error: "Email is required" });
    }

    const user = await getUserByEmail(email);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    res.status(200).json({ user });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/alluser", async (req, res) => {
  try {
    const users = await query(
      `SELECT ${USER_PUBLIC_SELECT} FROM users WHERE role = ? ORDER BY id DESC`,
      ["user"]
    );
    res.json(mapUsers(users));
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/allflatesfind", async (req, res) => {
  try {
    const flats = await query(
      `SELECT ${FLAT_SELECT} FROM rental_flats ORDER BY id DESC`
    );
    res.json(flats);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/alltenant", async (req, res) => {
  try {
    const tenants = await query(
      `SELECT ${USER_PUBLIC_SELECT} FROM users WHERE role = ? ORDER BY id DESC`,
      ["tenant"]
    );
    res.json(mapUsers(tenants));
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete("/deleteUser/:id", async (req, res) => {
  try {
    await query("DELETE FROM users WHERE id = ?", [req.params.id]);
    res.json({ message: "successfully deleted" });
  } catch (error) {
    console.error(error);
    res.json({ message: error.message });
  }
});

app.post("/submitquery", async (req, res) => {
  try {
    const { name, flatno, mobileno, service } = req.body;

    await query(
      "INSERT INTO service_queries (name, flatno, mobileno, service) VALUES (?, ?, ?, ?)",
      [name, flatno, mobileno, service]
    );

    res.status(201).json({ message: "User query submit successfully" });
  } catch (error) {
    console.error("Error during user register query:", error);
    res.status(400).json({ error: error.message });
  }
});

app.get("/getallUSer", async (req, res) => {
  try {
    const queries = await query(
      `SELECT ${QUERY_SELECT} FROM service_queries ORDER BY id DESC`
    );
    res.json(queries);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete("/deleteQuery/:id", async (req, res) => {
  try {
    await query("DELETE FROM service_queries WHERE id = ?", [req.params.id]);
    res.json({ message: "successfully deleted" });
  } catch (error) {
    console.error(error);
    res.json({ message: error.message });
  }
});

async function startServer() {
  try {
    await ensureAppReady();
    app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
  } catch (error) {
    console.error("Failed to start server:", error);
    process.exit(1);
  }
}

function ensureAppReady() {
  if (!appReadyPromise) {
    appReadyPromise = initDb();
  }

  return appReadyPromise;
}

if (require.main === module) {
  startServer();
}

module.exports = app;
module.exports.ensureAppReady = ensureAppReady;
module.exports.startServer = startServer;
