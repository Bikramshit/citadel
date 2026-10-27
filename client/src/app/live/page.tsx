import type { Metadata } from "next";
import { Live } from "@/components/views/live";

export const metadata: Metadata = { title: "Live" };

export default function Page() {
  return <Live />;
}
