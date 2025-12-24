import nodemailer from "nodemailer";
import dotenv from "dotenv";
dotenv.config();

const transporter = nodemailer.createTransport({
  host: "smtp.mailgun.org",
  port: 587,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

async function sendTest() {
  try {
    const info = await transporter.sendMail({
      from: `Secrets App <${process.env.EMAIL_USER}>`,
      to: "YOUR_VERIFIED_EMAIL@gmail.com", // must be verified in sandbox
      subject: "Test Email",
      html: "<p>This is a test email from Mailgun sandbox.</p>"
    });
    console.log("Email sent:", info.messageId);
  } catch (err) {
    console.error("Error:", err);
  }
}

sendTest();
