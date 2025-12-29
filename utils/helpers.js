import bcrypt from "bcryptjs";

// ----- HASH PASSWORD -----
export const hashPassword = async (plainPassword) => {
  const salt = await bcrypt.genSalt(12);
  return await bcrypt.hash(plainPassword, salt);
};

// ----- COMPARE PASSWORD -----
export const comparePassword = async (plainPassword, hashedPassword) => {
  return await bcrypt.compare(plainPassword, hashedPassword);
};

// ----- SIMPLE EMAIL VALIDATION -----
export const validateEmail = (email) => {
  const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return regex.test(email.toLowerCase());
};
