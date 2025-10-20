# Counselor Notes – FERPA-Compliant Backend

Counselor Notes is a secure web platform designed to help school counselors manage and protect student information in compliance with FERPA regulations.  
This repository contains the backend server built with Node.js and Express, focusing on data protection, scalability, and user privacy.

## Overview

The backend powers the Counselor Notes web app by handling authentication, authorization, secure data storage, and audit logging.  
It uses AWS services to provide reliability and compliance-grade security.

## Features

- FERPA-compliant architecture with secure data retention and deletion controls  
- Multi-factor authentication (SMS and TOTP)  
- Role-based access control for counselors and administrators  
- Encrypted note storage in AWS DynamoDB and file management through S3  
- Audit logging for every access or modification event  
- Session and JWT-based authentication with strict access gating  
- Configurable privacy policy and consent verification system  

## Tech Stack

- Node.js  
- Express.js  
- AWS DynamoDB, S3, SNS, CloudTrail  
- Speakeasy (TOTP)  
- Twilio or AWS SNS (for SMS MFA)  
- JSON Web Tokens (JWT)  
- bcrypt for password hashing  

## Setup

1. Clone the repository  
   ```bash
   git clone https://github.com/yourusername/counselor-notes-backend.git
Install dependencies

bash
Copy code
npm install
Create a .env file with your configuration values (see example below)

Run the development server

bash
Copy code
npm run dev
Example .env
bash
Copy code
PORT=8080
JWT_SECRET=your_jwt_secret
AWS_REGION=us-west-2
DYNAMO_TABLE=CounselorNotes
S3_BUCKET=counselor-notes-storage
SNS_TOPIC_ARN=your_sns_topic
TOTP_ISSUER=CounselorNotes
Folder Structure
bash
Copy code
/src
 ├── routes/         # Express routes for authentication, notes, and admin
 ├── controllers/    # Logic for handling API requests
 ├── models/         # DynamoDB schemas and data interfaces
 ├── middleware/     # Authentication and role-based access checks
 ├── utils/          # Helper functions for encryption, logging, etc.
 ├── config/         # AWS, environment, and security configuration
 └── server.js       # Main Express server entry point
Key Design Highlights
Designed around the principle of least privilege and granular access control

All sensitive data encrypted at rest and in transit

Built-in audit logging and session expiration handling

FERPA-aligned privacy policy route and consent enforcement

Modular architecture for scalability and maintainability

License
This project is licensed under the MIT License.
See the LICENSE file for more information.
