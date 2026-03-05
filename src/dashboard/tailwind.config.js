/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        nb: {
          primary: "rgb(var(--nb-primary) / <alpha-value>)",
          secondary: "rgb(var(--nb-secondary) / <alpha-value>)",
        },
      },
    },
  },
  plugins: [],
};
