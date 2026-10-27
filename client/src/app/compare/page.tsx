import type { Metadata } from "next";
import { Compare } from "@/components/views/compare";

export const metadata: Metadata = { title: "Compare" };

export default function Page() {
  return <Compare />;
}
