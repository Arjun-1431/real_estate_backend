require("dotenv").config();

const mysql = require("mysql2/promise");

const databaseName = process.env.MYSQL_DATABASE || "arjun_real_estate_objectnote";
const sslEnabled = String(process.env.MYSQL_SSL || "true").toLowerCase() !== "false";

function requireEnv(name) {
  const value = process.env[name];

  if (!value) {
    throw new Error(`${name} is required for the MySQL connection.`);
  }

  return value;
}

if (!/^[A-Za-z0-9_]+$/.test(databaseName)) {
  throw new Error("MYSQL_DATABASE should only contain letters, numbers, and underscores.");
}

const baseConfig = {
  host: requireEnv("MYSQL_HOST"),
  port: Number(process.env.MYSQL_PORT || 18499),
  user: requireEnv("MYSQL_USER"),
  password: requireEnv("MYSQL_PASSWORD"),
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
};

if (sslEnabled) {
  baseConfig.ssl = { rejectUnauthorized: false };
}

let pool;

async function ensureDatabase() {
  const adminPool = mysql.createPool(baseConfig);

  try {
    await adminPool.query(`CREATE DATABASE IF NOT EXISTS \`${databaseName}\``);
  } finally {
    await adminPool.end();
  }
}

async function createTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
      name VARCHAR(150) NOT NULL,
      email VARCHAR(191) NOT NULL UNIQUE,
      password VARCHAR(255) NOT NULL,
      mobile VARCHAR(20) DEFAULT NULL,
      is_admin TINYINT(1) NOT NULL DEFAULT 0,
      person_uuid VARCHAR(36) DEFAULT NULL,
      role VARCHAR(50) NOT NULL DEFAULT 'user',
      reset_password_token VARCHAR(255) DEFAULT NULL,
      reset_password_expires BIGINT DEFAULT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS contact_messages (
      id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
      emailid VARCHAR(191) NOT NULL,
      subject VARCHAR(255) NOT NULL,
      message TEXT NOT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS documents (
      id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
      object_id VARCHAR(50) NOT NULL,
      name VARCHAR(191) NOT NULL,
      doc VARCHAR(255) NOT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_documents_object_id (object_id)
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS news (
      id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
      heading VARCHAR(255) NOT NULL,
      images VARCHAR(255) NOT NULL,
      newsdiscription TEXT,
      date DATE DEFAULT NULL,
      link_url VARCHAR(500) DEFAULT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS rental_flats (
      id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
      flatlocation VARCHAR(255) NOT NULL,
      pricing VARCHAR(50) NOT NULL,
      rating DECIMAL(3,1) DEFAULT NULL,
      sqtfoot INT DEFAULT NULL,
      bedroom INT DEFAULT NULL,
      beds INT DEFAULT NULL,
      imagesq VARCHAR(255) NOT NULL,
      person_id VARCHAR(50) NOT NULL,
      name VARCHAR(150) NOT NULL,
      email VARCHAR(191) NOT NULL,
      conte VARCHAR(20) NOT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_rental_flats_person_id (person_id)
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS service_queries (
      id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
      name VARCHAR(150) NOT NULL,
      flatno VARCHAR(100) NOT NULL,
      mobileno VARCHAR(20) NOT NULL,
      service VARCHAR(255) NOT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS email_verifications (
      id VARCHAR(36) NOT NULL PRIMARY KEY,
      purpose VARCHAR(30) NOT NULL,
      email VARCHAR(191) NOT NULL,
      code_hash VARCHAR(64) NOT NULL,
      payload_json LONGTEXT NOT NULL,
      expires_at BIGINT NOT NULL,
      attempts_left INT NOT NULL DEFAULT 5,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_email_verifications_expires_at (expires_at),
      INDEX idx_email_verifications_email (email)
    )
  `);
}

async function initDb() {
  if (pool) {
    return pool;
  }

  await ensureDatabase();
  pool = mysql.createPool({
    ...baseConfig,
    database: databaseName,
  });

  await createTables();
  console.log(`MySQL connected on ${baseConfig.host}:${baseConfig.port}/${databaseName}`);
  return pool;
}

async function query(sql, params = []) {
  if (!pool) {
    await initDb();
  }

  const [rows] = await pool.execute(sql, params);
  return rows;
}

module.exports = {
  initDb,
  query,
};
