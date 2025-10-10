require("dotenv").config();
const { DynamoDBClient } = require("@aws-sdk/client-dynamodb");
const { DynamoDBDocumentClient } = require("@aws-sdk/lib-dynamodb");

// Allow dynamic switching between local and AWS DynamoDB
const isLocal =
  process.env.NODE_ENV === "development" || process.env.DYNAMODB_ENDPOINT;

const client = new DynamoDBClient({
  region: process.env.DYNAMODB_REGION || "us-west-2",
  ...(isLocal && {
    endpoint: process.env.DYNAMODB_ENDPOINT || "http://localhost:8000",
    credentials: {
      accessKeyId: "fakeMyKeyId", // required for local DynamoDB
      secretAccessKey: "fakeSecretAccessKey",
    },
  }),
});

const db = DynamoDBDocumentClient.from(client);

module.exports = db;
