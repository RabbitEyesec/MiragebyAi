import { notFound } from "next/navigation";

import { DashboardApp } from "@/components/DashboardApp";

export default async function TestFixturePage({
  searchParams,
}: {
  searchParams: Promise<{ restricted?: string }>;
}) {
  if (process.env.MIRAGE_E2E_FIXTURE !== "1") notFound();
  const restricted = (await searchParams).restricted === "1";
  return (
    <DashboardApp
      initialUser={{
        subject: "e2e-user",
        username: "e2e-investigator",
        roles: restricted
          ? ["investigator"]
          : [
              "platform_admin",
              "investigator",
              "operator",
              "auditor",
              "read_only",
              "export",
              "direct_intervention",
              "emergency_control",
            ],
        expiresAt: 4102444800,
      }}
    />
  );
}
