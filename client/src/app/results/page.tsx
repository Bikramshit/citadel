import type { Metadata } from "next";
import { Results } from "@/components/views/results";

export const metadata: Metadata = { title: "Results" };

export default function Page() {
  return <Results />;
}
