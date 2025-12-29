import pkg from "pg";
const { Pool } = pkg;

export const db = new Pool({
  user: process.env.DB_USER || "postgres",
  host: process.env.DB_HOST || "localhost",
  database: process.env.DB_NAME || "socialapp",
  password: process.env.DB_PASSWORD || "password",
  port: process.env.DB_PORT || 5432,
});

db.connect()
  .then(() => console.log("Connected to DB"))
  .catch((err) => console.error("DB Connection Error:", err));
