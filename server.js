require("dotenv").config();

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const db = require("./db");


const app = express();

const PORT = process.env.PORT || 3000;

const JWT_SECRET = process.env.JWT_SECRET;


app.use(cors());

app.use(express.json());


/* =========================
   BASIC HEALTH CHECK
========================= */

app.get("/api/health", (req, res) => {

    res.json({
        success: true,
        message: "B-RACHEAL backend is running."
    });

});


/* =========================
   HELPER FUNCTIONS
========================= */

function createToken(user) {

    return jwt.sign(
        {
            id: user.id,
            role: user.role,
            username: user.username,
            fullName: user.full_name
        },
        JWT_SECRET,
        {
            expiresIn: "12h"
        }
    );

}


function generatePatientId() {

    const year = new Date().getFullYear();

    const randomPart = crypto
        .randomBytes(4)
        .toString("hex")
        .toUpperCase();

    return `BR-${year}-${randomPart}`;

}


function getTokenFromRequest(req) {

    const header = req.headers.authorization;

    if (!header) {
        return null;
    }

    if (!header.startsWith("Bearer ")) {
        return null;
    }

    return header.substring(7);

}


/* =========================
   AUTHENTICATION MIDDLEWARE
========================= */

function authenticate(req, res, next) {

    const token = getTokenFromRequest(req);

    if (!token) {

        return res.status(401).json({
            success: false,
            message: "Authentication required."
        });

    }


    try {

        const decoded = jwt.verify(
            token,
            JWT_SECRET
        );

        req.user = decoded;

        next();

    } catch (error) {

        return res.status(401).json({
            success: false,
            message: "Invalid or expired session."
        });

    }

}


/* =========================
   MD-ONLY MIDDLEWARE
========================= */

function requireMD(req, res, next) {

    if (!req.user || req.user.role !== "md") {

        return res.status(403).json({
            success: false,
            message: "MD / Doctor access required."
        });

    }

    next();

}


/* =========================
   STAFF / MD ACCESS
========================= */

function requireStaffOrMD(req, res, next) {

    if (
        !req.user ||
        (
            req.user.role !== "staff" &&
            req.user.role !== "md"
        )
    ) {

        return res.status(403).json({
            success: false,
            message: "Authorized staff access required."
        });

    }

    next();

}


/* =========================
   SEED MD ACCOUNT
========================= */

async function createMDAccount() {

    const mdUsername = process.env.MD_USERNAME;
    const mdEmail = process.env.MD_EMAIL;
    const mdPassword = process.env.MD_PASSWORD;


    if (
        !mdUsername ||
        !mdEmail ||
        !mdPassword
    ) {

        console.log(
            "MD account environment variables are missing."
        );

        return;

    }


    const existing = await db.get(
        `
        SELECT id
        FROM users
        WHERE role = 'md'
        LIMIT 1
        `
    );


    if (existing) {

        console.log("MD account already exists.");

        return;

    }


    const passwordHash = await bcrypt.hash(
        mdPassword,
        12
    );


    await db.run(
        `
        INSERT INTO users
        (
            full_name,
            username,
            email,
            password_hash,
            role,
            status
        )
        VALUES (?, ?, ?, ?, 'md', 'active')
        `,
        [
            mdUsername,
            mdUsername,
            mdEmail,
            passwordHash
        ]
    );


    console.log(
        "MD account created successfully."
    );

}


/* =========================
   STAFF REGISTRATION
========================= */

app.post(
    "/api/staff/register",
    async (req, res) => {

        try {

            const {
                fullName,
                username,
                email,
                password
            } = req.body;


            if (
                !fullName ||
                !username ||
                !email ||
                !password
            ) {

                return res.status(400).json({
                    success: false,
                    message: "All fields are required."
                });

            }


            if (password.length < 6) {

                return res.status(400).json({
                    success: false,
                    message: "Password must be at least 6 characters."
                });

            }


            const existing = await db.get(
                `
                SELECT id
                FROM users
                WHERE username = ?
                   OR email = ?
                LIMIT 1
                `,
                [
                    username.trim(),
                    email.trim().toLowerCase()
                ]
            );


            if (existing) {

                return res.status(409).json({
                    success: false,
                    message: "Username or email already exists."
                });

            }


            const passwordHash = await bcrypt.hash(
                password,
                12
            );


            await db.run(
                `
                INSERT INTO users
                (
                    full_name,
                    username,
                    email,
                    password_hash,
                    role,
                    status
                )
                VALUES (?, ?, ?, ?, 'staff', 'pending')
                `,
                [
                    fullName.trim(),
                    username.trim(),
                    email.trim().toLowerCase(),
                    passwordHash
                ]
            );


            res.status(201).json({
                success: true,
                message:
                    "Account registered successfully. Pending MD approval."
            });


        } catch (error) {

            console.error(
                "Staff registration error:",
                error
            );


            res.status(500).json({
                success: false,
                message: "Unable to register staff account."
            });

        }

    }
);


/* =========================
   LOGIN
========================= */

app.post(
    "/api/auth/login",
    async (req, res) => {

        try {

            const {
                username,
                password,
                role
            } = req.body;


            if (
                !username ||
                !password ||
                !role
            ) {

                return res.status(400).json({
                    success: false,
                    message: "Username, password and account type are required."
                });

            }


            const user = await db.get(
                `
                SELECT
                    id,
                    full_name,
                    username,
                    email,
                    password_hash,
                    role,
                    status
                FROM users
                WHERE username = ?
                   OR email = ?
                LIMIT 1
                `,
                [
                    username.trim(),
                    username.trim().toLowerCase()
                ]
            );


            if (!user) {

                return res.status(401).json({
                    success: false,
                    message: "Invalid username or password."
                });

            }


            if (user.role !== role) {

                return res.status(401).json({
                    success: false,
                    message: "Incorrect account type."
                });

            }


            if (user.status === "pending") {

                return res.status(403).json({
                    success: false,
                    message:
                        "Your staff account is still pending MD approval."
                });

            }


            if (user.status === "closed") {

                return res.status(403).json({
                    success: false,
                    message:
                        "Your account access has been closed by the MD."
                });

            }


            const passwordMatches = await bcrypt.compare(
                password,
                user.password_hash
            );


            if (!passwordMatches) {

                return res.status(401).json({
                    success: false,
                    message: "Invalid username or password."
                });

            }


            const token = createToken(user);


            res.json({

                success: true,

                token,

                user: {
                    id: user.id,
                    fullName: user.full_name,
                    username: user.username,
                    email: user.email,
                    role: user.role,
                    status: user.status
                }

            });


        } catch (error) {

            console.error(
                "Login error:",
                error
            );


            res.status(500).json({
                success: false,
                message: "Login failed."
            });

        }

    }
);


/* =========================
   GET STAFF
========================= */

app.get(
    "/api/staff",
    authenticate,
    requireMD,
    async (req, res) => {

        try {

            const staff = await db.all(
                `
                SELECT
                    id,
                    full_name,
                    username,
                    email,
                    status,
                    created_at,
                    approved_at,
                    closed_at
                FROM users
                WHERE role = 'staff'
                ORDER BY id DESC
                `
            );


            const formattedStaff = staff.map(user => ({

                id: user.id,

                fullName: user.full_name,

                username: user.username,

                email: user.email,

                status: user.status,

                createdAt: user.created_at,

                approvedAt: user.approved_at,

                closedAt: user.closed_at

            }));


            res.json({
                success: true,
                staff: formattedStaff
            });


        } catch (error) {

            console.error(
                "Get staff error:",
                error
            );


            res.status(500).json({
                success: false,
                message: "Unable to load staff."
            });

        }

    }
);

   /* =========================
   APPROVE STAFF
========================= */

app.put(
    "/api/staff/:id/approve",
    authenticate,
    requireMD,
    async (req, res) => {

        try {

            const staffId = Number(req.params.id);

            if (!Number.isInteger(staffId)) {

                return res.status(400).json({
                    success: false,
                    message: "Invalid staff ID."
                });

            }

            const staff = await db.get(
                `
                SELECT id, status
                FROM users
                WHERE id = ?
                  AND role = 'staff'
                `,
                [staffId]
            );

            if (!staff) {

                return res.status(404).json({
                    success: false,
                    message: "Staff account not found."
                });

            }

            await db.run(
                `
                UPDATE users
                SET
                    status = 'active',
                    approved_at = CURRENT_TIMESTAMP,
                    closed_at = NULL
                WHERE id = ?
                  AND role = 'staff'
                `,
                [staffId]
            );

            res.json({
                success: true,
                message: "Staff account approved successfully."
            });

        } catch (error) {

            console.error(
                "Approve staff error:",
                error
            );

            res.status(500).json({
                success: false,
                message: "Unable to approve staff account."
            });

        }

    }
);
/* =========================
   CLOSE STAFF ACCESS
========================= */

app.put(
    "/api/staff/:id/close",
    authenticate,
    requireMD,
    async (req, res) => {

        try {

            const staffId = Number(req.params.id);

            if (!Number.isInteger(staffId)) {

                return res.status(400).json({
                    success: false,
                    message: "Invalid staff ID."
                });

            }

            const staff = await db.get(
                `
                SELECT id, status
                FROM users
                WHERE id = ?
                  AND role = 'staff'
                `,
                [staffId]
            );

            if (!staff) {

                return res.status(404).json({
                    success: false,
                    message: "Staff account not found."
                });

            }

            await db.run(
                `
                UPDATE users
                SET
                    status = 'closed',
                    closed_at = CURRENT_TIMESTAMP
                WHERE id = ?
                  AND role = 'staff'
                `,
                [staffId]
            );

            res.json({
                success: true,
                message: "Staff access closed successfully."
            });

        } catch (error) {

            console.error(
                "Close staff error:",
                error
            );

            res.status(500).json({
                success: false,
                message: "Unable to close staff access."
            });

        }

    }
);
 /* =========================
   REGISTER PATIENT
========================= */

app.post(
    "/api/patients",
    authenticate,
    requireStaffOrMD,
    async (req, res) => {

        try {

            const {
                name,
                sex,
                dateOfBirth,
                phone,
                address,
                nextOfKin,
                nextOfKinPhone
            } = req.body;


            if (!name || !name.trim()) {

                return res.status(400).json({
                    success: false,
                    message: "Patient name is required."
                });

            }


            let patientId;

            let inserted = false;

            let attempts = 0;


            while (!inserted && attempts < 5) {

                attempts++;

                patientId = generatePatientId();


                try {

                    await db.run(
                        `
                        INSERT INTO patients
                        (
                            patient_id,
                            name,
                            sex,
                            date_of_birth,
                            phone,
                            address,
                            next_of_kin,
                            next_of_kin_phone,
                            created_by
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        `,
                        [
                            patientId,
                            name.trim(),
                            sex || null,
                            dateOfBirth || null,
                            phone || null,
                            address || null,
                            nextOfKin || null,
                            nextOfKinPhone || null,
                            req.user.id
                        ]
                    );


                    inserted = true;


                } catch (error) {

                    if (attempts >= 5) {
                        throw error;
                    }

                }

            }


            res.status(201).json({

                success: true,

                message: "Patient registered successfully.",

                patient: {
                    patientId
                }

            });


        } catch (error) {

            console.error(
                "Register patient error:",
                error
            );


            res.status(500).json({
                success: false,
                message: "Unable to register patient."
            });

        }

    }
);


/* =========================
   SEARCH PATIENTS
========================= */

app.get(
    "/api/patients/search",
    authenticate,
    requireStaffOrMD,
    async (req, res) => {

        try {

            const q = String(
                req.query.q || ""
            ).trim();


            if (!q) {

                return res.json({
                    success: true,
                    patients: []
                });

            }


            const searchTerm = `%${q}%`;


            const patients = await db.all(
                `
                SELECT
                    id,
                    patient_id,
                    name,
                    sex,
                    date_of_birth,
                    phone,
                    address,
                    next_of_kin,
                    next_of_kin_phone,
                    created_at,
                    updated_at
                FROM patients
                WHERE name LIKE ?
                   OR patient_id LIKE ?
                ORDER BY id DESC
                LIMIT 50
                `,
                [
                    searchTerm,
                    searchTerm
                ]
            );


            const formattedPatients = patients.map(patient => ({

                id: patient.id,

                patientId: patient.patient_id,

                name: patient.name,

                sex: patient.sex,

                dateOfBirth: patient.date_of_birth,

                phone: patient.phone,

                address: patient.address,

                nextOfKin: patient.next_of_kin,

                nextOfKinPhone: patient.next_of_kin_phone,

                createdAt: patient.created_at,

                updatedAt: patient.updated_at

            }));


            res.json({

                success: true,

                patients: formattedPatients

            });


        } catch (error) {

            console.error(
                "Patient search error:",
                error
            );


            res.status(500).json({
                success: false,
                message: "Unable to search patients."
            });

        }

    }
);


/* =========================
   GET COMPLETE PATIENT RECORD
========================= */

app.get(
    "/api/patients/:id",
    authenticate,
    requireStaffOrMD,
    async (req, res) => {

        try {

            const patientId = Number(
                req.params.id
            );


            if (!Number.isInteger(patientId)) {

                return res.status(400).json({
                    success: false,
                    message: "Invalid patient ID."
                });

            }


            const patient = await db.get(
                `
                SELECT
                    id,
                    patient_id,
                    name,
                    sex,
                    date_of_birth,
                    phone,
                    address,
                    next_of_kin,
                    next_of_kin_phone,
                    created_at,
                    updated_at
                FROM patients
                WHERE id = ?
                LIMIT 1
                `,
                [patientId]
            );


            if (!patient) {

                return res.status(404).json({
                    success: false,
                    message: "Patient not found."
                });

            }


            const treatments = await db.all(
                `
                SELECT
                    t.id,
                    t.date,
                    t.time,
                    t.details,
                    t.created_at,
                    u.full_name AS recorded_by
                FROM treatments t
                LEFT JOIN users u
                    ON u.id = t.recorded_by
                WHERE t.patient_id = ?
                ORDER BY
                    t.date DESC,
                    t.time DESC,
                    t.id DESC
                `,
                [patientId]
            );


            res.json({

                success: true,

                patient: {

                    id: patient.id,

                    patientId: patient.patient_id,

                    name: patient.name,

                    sex: patient.sex,

                    dateOfBirth: patient.date_of_birth,

                    phone: patient.phone,

                    address: patient.address,

                    nextOfKin: patient.next_of_kin,

                    nextOfKinPhone:
                        patient.next_of_kin_phone,

                    createdAt:
                        patient.created_at,

                    updatedAt:
                        patient.updated_at,

                    treatments: treatments.map(
                        treatment => ({

                            id: treatment.id,

                            date: treatment.date,

                            time: treatment.time,

                            details:
                                treatment.details,

                            recordedBy:
                                treatment.recorded_by ||
                                "Unknown",

                            createdAt:
                                treatment.created_at

                        })
                    )

                }

            });


        } catch (error) {

            console.error(
                "Get patient record error:",
                error
            );


            res.status(500).json({
                success: false,
                message: "Unable to load patient record."
            });

        }

    }
);


/* =========================
   UPDATE PATIENT
========================= */

app.put(
    "/api/patients/:id",
    authenticate,
    requireStaffOrMD,
    async (req, res) => {

        try {

            const patientId = Number(
                req.params.id
            );


            if (!Number.isInteger(patientId)) {

                return res.status(400).json({
                    success: false,
                    message: "Invalid patient ID."
                });

            }


            const {
                name,
                sex,
                dateOfBirth,
                phone,
                address,
                nextOfKin,
                nextOfKinPhone
            } = req.body;


            if (!name || !name.trim()) {

                return res.status(400).json({
                    success: false,
                    message: "Patient name is required."
                });

            }


            const result = await db.run(
                `
                UPDATE patients
                SET
                    name = ?,
                    sex = ?,
                    date_of_birth = ?,
                    phone = ?,
                    address = ?,
                    next_of_kin = ?,
                    next_of_kin_phone = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                `,
                [
                    name.trim(),
                    sex || null,
                    dateOfBirth || null,
                    phone || null,
                    address || null,
                    nextOfKin || null,
                    nextOfKinPhone || null,
                    patientId
                ]
            );


            if (!result.rowsAffected) {

                return res.status(404).json({
                    success: false,
                    message: "Patient not found."
                });

            }


            res.json({

                success: true,

                message:
                    "Patient record updated successfully."

            });


        } catch (error) {

            console.error(
                "Update patient error:",
                error
            );


            res.status(500).json({
                success: false,
                message: "Unable to update patient record."
            });

        }

    }
);


/* =========================
   ADD TREATMENT
========================= */

app.post(
    "/api/patients/:id/treatments",
    authenticate,
    requireStaffOrMD,
    async (req, res) => {

        try {

            const patientId = Number(
                req.params.id
            );


            if (!Number.isInteger(patientId)) {

                return res.status(400).json({
                    success: false,
                    message: "Invalid patient ID."
                });

            }


            const {
                date,
                time,
                details
            } = req.body;


            if (
                !date ||
                !time ||
                !details ||
                !details.trim()
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Treatment date, time and details are required."
                });

            }


            const patient = await db.get(
                `
                SELECT id
                FROM patients
                WHERE id = ?
                LIMIT 1
                `,
                [patientId]
            );


            if (!patient) {

                return res.status(404).json({
                    success: false,
                    message: "Patient not found."
                });

            }


            await db.run(
                `
                INSERT INTO treatments
                (
                    patient_id,
                    date,
                    time,
                    details,
                    recorded_by
                )
                VALUES (?, ?, ?, ?, ?)
                `,
                [
                    patientId,
                    date,
                    time,
                    details.trim(),
                    req.user.id
                ]
            );


            res.status(201).json({

                success: true,

                message:
                    "Treatment record saved successfully."

            });


        } catch (error) {

            console.error(
                "Add treatment error:",
                error
            );


            res.status(500).json({
                success: false,
                message: "Unable to save treatment record."
            });

        }

    }
);


/* =========================
   START SERVER
========================= */

async function startServer() {

    try {

        if (!JWT_SECRET) {

            throw new Error(
                "JWT_SECRET is missing from .env"
            );

        }


        await createMDAccount();


        app.listen(
            PORT,
            () => {

                console.log("");
                console.log(
                    "======================================"
                );

                console.log(
                    "       B-RACHEAL BACKEND SERVER"
                );

                console.log(
                    "======================================"
                );

                console.log(
                    `Server running on http://localhost:${PORT}`
                );

                console.log(
                    `Health check: http://localhost:${PORT}/api/health`
                );

                console.log(
                    "======================================"
                );

                console.log("");

            }
        );


    } catch (error) {

        console.error(
            "Failed to start B-RACHEAL backend:"
        );

        console.error(error);

        process.exit(1);

    }

}


startServer();
