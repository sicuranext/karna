/* The Karna mark.
   Assets are vendored from docs/assets and bundled by Vite — no CDN. */
import markLight from "../assets/karna-mark-bold.svg";
import sicuranextMark from "../assets/sicuranext-mark.png";

export function Brand({ size = 30, alt = "Karna" }) {
  return (
    <img
      src={markLight}
      width={size}
      height={size}
      alt={alt}
      style={{ display: "block", objectFit: "contain" }}
    />
  );
}

/* "By SicuraNext" signature. */
export function PoweredBy() {
  return (
    <span className="powered-by">
      <span>By</span>
      <img src={sicuranextMark} alt="SicuraNext" width="1154" height="156" />
    </span>
  );
}
