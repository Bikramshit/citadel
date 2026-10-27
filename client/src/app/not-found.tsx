import Link from "next/link";

export default function NotFound() {
  return (
    <div className="py-24 text-center">
      <p className="font-mono text-[12px] uppercase tracking-[0.16em] text-muted">404</p>
      <h1 className="mt-2 text-2xl font-semibold text-ink">Nothing here</h1>
      <Link href="/" className="mt-4 inline-block text-[14px] font-medium text-accent-ink hover:underline">
        Back to the overview
      </Link>
    </div>
  );
}
