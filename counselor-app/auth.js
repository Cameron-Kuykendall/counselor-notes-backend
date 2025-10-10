require("dotenv").config();
const bcrypt = require("bcrypt");
const {
  SecretsManagerClient,
  GetSecretValueCommand,
} = require("@aws-sdk/client-secrets-manager");

let cachedPepper = null;
async function getPepper() {
  if (cachedPepper) return cachedPepper;
  // Try AWS Secrets Manager first
  try {
    const client = new SecretsManagerClient({
      region: process.env.AWS_REGION || "us-west-2",
    });
    const command = new GetSecretValueCommand({ SecretId: "CounselorPepper" });
    const data = await client.send(command);
    // Support both plain string and JSON
    try {
      const secret = JSON.parse(data.SecretString);
      cachedPepper = secret.pepper || data.SecretString;
    } catch {
      cachedPepper = data.SecretString;
    }
    return cachedPepper;
  } catch (err) {
    if (process.env.NODE_ENV !== "production") {
      console.warn("Falling back to .env pepper:", err.message);
    }
    if (process.env.PEPPER) return process.env.PEPPER;
    throw new Error("Pepper not found in AWS Secrets Manager or .env");
  }
}

async function hashPassword(password) {
  const pepper = await getPepper();
  return await bcrypt.hash(password + pepper, 12);
}

async function comparePassword(password, hash) {
  const pepper = await getPepper();
  return await bcrypt.compare(password + pepper, hash);
}

module.exports = { hashPassword, comparePassword };
