/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./views/**/*.ejs",   // Tailwind scans your EJS files
    "./public/**/*.js"    // Optional: if using Tailwind classes in JS
  ],
  theme: {
    extend: {},
  },
  plugins: [],
};
