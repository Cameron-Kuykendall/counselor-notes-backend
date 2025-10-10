const { SESClient, SendEmailCommand } = require("@aws-sdk/client-ses");

const ses = new SESClient({ region: process.env.AWS_REGION || process.env.DYNAMODB_REGION || "us-west-2" });

/**
 * Send an email via AWS SES
 * @param {string} to - recipient email address
 * @param {string} subject - subject line
 * @param {string} bodyText - plaintext body
 * @param {string|null} bodyHtml - optional HTML body
 */
async function sendEmail(to, subject, bodyText, bodyHtml = null) {
  const params = {
    Source: process.env.EMAIL_FROM,
    Destination: { ToAddresses: [to] },
    Message: {
      Subject: { Data: subject },
      Body: {
        Text: { Data: bodyText },
        ...(bodyHtml ? { Html: { Data: bodyHtml } } : {}),
      },
    },
  };

  const command = new SendEmailCommand(params);
  await ses.send(command);
}

module.exports = { sendEmail };
