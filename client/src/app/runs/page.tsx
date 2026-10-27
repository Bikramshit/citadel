import type { Metadata } from "next";
import { Runs } from "@/components/views/runs";

export const metadata: Metadata = { title: "Runs" };

export default function Page() {
  return <Runs />;
}
