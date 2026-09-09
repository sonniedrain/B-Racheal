require("dotenv").config();

const db = require("./db");


async function setupDatabase() {

    console.log("Connecting to Turso...");


    await db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            full_name TEXT NOT NULL,

            username TEXT NOT NULL UNIQUE,

            email TEXT NOT NULL UNIQUE,

            password_hash TEXT NOT NULL,

            role TEXT NOT NULL DEFAULT 'staff',

            status TEXT NOT NULL DEFAULT 'pending',

            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

            approved_at TEXT,

            closed_at TEXT
        )
    `);


    console.log("Users table ready.");


    await db.run(`
        CREATE TABLE IF NOT EXISTS patients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            patient_id TEXT NOT NULL UNIQUE,

            name TEXT NOT NULL,

            sex TEXT,

            date_of_birth TEXT,

            phone TEXT,

            address TEXT,

            next_of_kin TEXT,

            next_of_kin_phone TEXT,

            created_by INTEGER,

            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (created_by)
                REFERENCES users(id)
        )
    `);


    console.log("Patients table ready.");


    await db.run(`
        CREATE TABLE IF NOT EXISTS treatments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            patient_id INTEGER NOT NULL,

            date TEXT NOT NULL,

            time TEXT NOT NULL,

            details TEXT NOT NULL,

            recorded_by INTEGER,

            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (patient_id)
                REFERENCES patients(id)
                ON DELETE CASCADE,

            FOREIGN KEY (recorded_by)
                REFERENCES users(id)
        )
    `);


    console.log("Treatments table ready.");


    console.log("Database setup completed successfully.");

}


setupDatabase()
    .catch(error => {

        console.error(
            "Database setup failed:"
        );

        console.error(error);

        process.exit(1);

    });
