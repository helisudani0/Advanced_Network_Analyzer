import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        ink: "#07111c",
        panel: "#0f1b2a",
        signal: "#54d8ff",
        ember: "#ff8b61"
      }
    }
  },
  plugins: []
};
export default config;
