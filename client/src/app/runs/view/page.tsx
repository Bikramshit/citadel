import type { Metadata } from "next";
import { Suspense } from "react";
import { RunView } from "@/components/views/run-view";
import { Skeleton } from "@/components/ui";

export const metadata: Metadata = { title: "Run" };

export default function Page() {
  return (
    <Suspense fallback={<Skeleton className="h-96" />}>
      <RunView />
    </Suspense>
  );
}
