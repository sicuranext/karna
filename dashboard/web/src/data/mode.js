/* Where the console's data comes from, chosen at build time (VITE_DATA_MODE):
 *   live   the FastAPI backend (the real console)
 *   demo   the sample data with writes applied in the browser (public live demo)
 *   sample the sample data, read-only (npm run dev) */
const requested = import.meta.env.VITE_DATA_MODE;
export const MODE = requested === "live" || requested === "demo" ? requested : "sample";
